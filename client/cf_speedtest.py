#!/usr/bin/env python3
"""Select or benchmark Cloudflare addresses for an existing VLESS WebSocket node."""

import argparse
import base64
import csv
import hashlib
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import statistics
import sys
import tempfile
import time
import urllib.parse as url
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DOWNLOAD_HOST = "speed.cloudflare.com"
CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
REPORT_VERSION = "1"
DEFAULT_SAMPLE = 24
DEFAULT_ATTEMPTS = 3
DEFAULT_WORKERS = 8
DEFAULT_TIMEOUT = 4
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def dns_name(value):
    name = value.encode("idna").decode("ascii").lower().removesuffix(".")
    if len(name) > 253 or not all(LABEL.fullmatch(label) for label in name.split(".")):
        raise ValueError("域名格式无效")
    return name


def address_value(value):
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" in value:
        raise ValueError("不支持带区域标识符的 IP 地址")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return dns_name(value)


@dataclass(frozen=True)
class Node:
    uri: url.SplitResult
    params: dict
    port: int
    sni: str
    host: str
    path: str

    @classmethod
    def from_file(cls, path):
        return cls.parse(path.read_text(encoding="utf-8-sig"))

    @classmethod
    def parse(cls, text):
        text = text.strip()
        if not text or any(char.isspace() for char in text):
            raise ValueError("URI 文件必须只含一行 VLESS 链接")
        parsed = url.urlsplit(text)
        if parsed.scheme != "vless" or not parsed.hostname or not parsed.username or parsed.password is not None:
            raise ValueError("URI 文件必须包含有效的 vless:// 链接")
        try:
            uuid.UUID(parsed.username)
        except ValueError:
            raise ValueError("VLESS UUID 格式无效") from None
        pairs = url.parse_qsl(parsed.query, keep_blank_values=True)
        params = dict(pairs)
        if len(params) != len(pairs) or params.get("security") != "tls" or params.get("type") != "ws":
            raise ValueError("需要 VLESS + WebSocket + TLS 链接，每个参数只能出现一次")
        sni = dns_name(params.get("sni") or parsed.hostname)
        host = dns_name(params.get("host") or sni)
        path = params.get("path") or "/"
        if not path.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in path):
            raise ValueError("WebSocket 路径无效")
        port = parsed.port if parsed.port is not None else 443
        if not port:
            raise ValueError("端口必须在 1 到 65535 之间")
        return cls(parsed, params, port, sni, host, url.quote(path, safe="/%?=&:+@!$'()*,-.;_~[]"))

    def target_fingerprint(self):
        # The probe tests the TLS and WebSocket target, without sending the VLESS UUID.
        target = json.dumps((self.sni, self.host, self.port, self.path), separators=(",", ":"))
        return hashlib.sha256(target.encode("ascii")).hexdigest()

    def link(self, address):
        if ":" in address:
            address = f"[{address}]"
        params = self.params | {"sni": self.sni, "host": self.host}
        return self.uri._replace(
            netloc=f"{self.uri.username}@{address}:{self.port}",
            query=url.urlencode(params),
        ).geturl()


def candidates(source, family, limit):
    explicit = {}
    networks = []
    for number, line in enumerate(source.splitlines(), 1):
        value = line.partition("#")[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
            if "%" in value:
                raise ValueError
        except ValueError:
            raise ValueError(f"候选列表第 {number} 行需要一个 IP 或 CIDR") from None
        if family and network.version != family:
            continue
        if network.num_addresses == 1:
            explicit[network.network_address] = None
        else:
            networks.append(network)

    rng = random.SystemRandom()
    picked = list(explicit)
    if len(picked) >= limit:
        return [str(ip) for ip in rng.sample(picked, limit)]
    disjoint = []
    for version in (4, 6):
        disjoint.extend(ipaddress.collapse_addresses(net for net in networks if net.version == version))
    rng.shuffle(disjoint)
    ranges = {}
    for network in disjoint:
        first = int(network.network_address)
        size = network.num_addresses
        if network.version == 4 and size > 2:
            first += 1
            size -= 2
        occupied = {int(ip) for ip in explicit if ip in network and first <= int(ip) < first + size}
        if len(occupied) < size:
            ranges[network] = (first, size, occupied)

    while len(picked) < limit and ranges:
        for network, (first, size, occupied) in list(ranges.items()):
            while (number := first + rng.randrange(size)) in occupied:
                pass
            occupied.add(number)
            if len(occupied) == size:
                del ranges[network]
            picked.append(type(network.network_address)(number))
            if len(picked) == limit:
                break
    return [str(ip) for ip in picked]


def load_candidates(args):
    if args.candidates:
        source = args.candidates.read_text(encoding="utf-8-sig")
        return candidates(source, args.family, args.sample)
    family = args.family or 4
    request = urllib.request.Request(CLOUDFLARE_IPS_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=args.timeout) as response:
        source = response.read(65537)
    if len(source) > 65536:
        raise ValueError("Cloudflare IP 列表超出预期大小")
    payload = json.loads(source)
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ValueError("Cloudflare IP 列表不可用")
    result = payload.get("result")
    networks = result.get(f"ipv{family}_cidrs") if isinstance(result, dict) else None
    if not isinstance(networks, list) or not networks or not all(isinstance(item, str) for item in networks):
        raise ValueError(f"Cloudflare IPv{family} 列表格式无效")
    return candidates("\n".join(networks), family, args.sample)


@contextmanager
def edge_response(ip, port, sni, host, path, headers, timeout, context):
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: chennixvpn-speedtest/1\r\n{headers}\r\n"
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        raise ProbeError(failure_message(exc, "TCP 连接")) from exc
    with raw:
        try:
            tls = context.wrap_socket(raw, server_hostname=sni)
        except OSError as exc:
            raise ProbeError(failure_message(exc, "TLS 握手")) from exc
        with tls:
            tls.sendall(request.encode("ascii"))
            with http.client.HTTPResponse(tls) as response:
                response.begin()
                yield response


@dataclass
class Result:
    ip: str
    attempts: int
    successes: int
    median_ms: float | None
    error: str
    mbps: float | None = None
    download_error: str = ""


class ProbeError(Exception):
    pass


def failure_message(error, operation="连接或读取"):
    if isinstance(error, ssl.SSLCertVerificationError):
        return "TLS 证书校验失败"
    if isinstance(error, TimeoutError):
        return f"{operation}超时"
    if isinstance(error, ProbeError):
        return str(error)
    return f"{operation}失败 ({type(error).__name__})"


def probe(ip, node, attempts, timeout, context):
    timings = []
    error = ""
    for _ in range(attempts):
        key = base64.b64encode(os.urandom(16))
        expected = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode("ascii")
        headers = (
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key.decode('ascii')}\r\n"
        )
        start = time.perf_counter()
        try:
            with edge_response(ip, node.port, node.sni, node.host, node.path, headers, timeout, context) as response:
                if response.status != 101:
                    raise ProbeError(f"HTTP {response.status}")
                connection = {part.strip().lower() for part in response.getheader("Connection", "").split(",")}
                if (response.getheader("Sec-WebSocket-Accept") != expected
                        or response.getheader("Upgrade", "").lower() != "websocket"
                        or "upgrade" not in connection):
                    raise ProbeError("WebSocket 握手校验失败")
                timings.append((time.perf_counter() - start) * 1000)
        except (OSError, http.client.HTTPException, ProbeError) as exc:
            error = failure_message(exc)
    return Result(ip, attempts, len(timings), statistics.median(timings) if timings else None, error)


def download(result, args, context):
    size = args.download_bytes
    # TCP port 443 belongs to Cloudflare's public benchmark endpoint.
    try:
        with edge_response(result.ip, 443, DOWNLOAD_HOST, DOWNLOAD_HOST, f"/__down?bytes={size}",
                           "Connection: close\r\nAccept-Encoding: identity\r\n", args.timeout, context) as response:
            if response.status != 200:
                raise ProbeError(f"HTTP {response.status}")
            start = time.perf_counter()
            remaining = size
            while remaining:
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    raise ProbeError("下载响应短于请求大小")
                remaining -= len(chunk)
                if time.perf_counter() - start > args.timeout:
                    raise TimeoutError
            result.mbps = size * 8 / max(time.perf_counter() - start, 0.000001) / 1_000_000
    except (OSError, http.client.HTTPException, ProbeError) as exc:
        result.download_error = failure_message(exc)


def rank_candidate(ip, attempts, successes, median_ms, download_mbps):
    latency = median_ms if median_ms is not None else float("inf")
    return -successes / attempts, latency, -(download_mbps or 0), ip


def rank(result):
    return rank_candidate(result.ip, result.attempts, result.successes, result.median_ms, result.mbps)


def write_csv(path, results, node, measured_at):
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = (REPORT_VERSION, node.target_fingerprint(), measured_at)
    with path.open("w", encoding="utf-8-sig", newline="") as out:
        rows = csv.writer(out)
        rows.writerow(["rank", "ip", "attempts", "successes", "failure_pct", "median_ms", "download_mbps",
                       "error", "download_error", "report_version", "target_fingerprint", "measured_at"])
        for number, result in enumerate(results, 1):
            rows.writerow([
                number, result.ip, result.attempts, result.successes,
                f"{100 * (1 - result.successes / result.attempts):.1f}",
                result.median_ms, result.mbps, result.error, result.download_error, *metadata,
            ])


def write_links(path, links):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, encoding="utf-8", newline="\n", delete=False, mode="w") as out:
        temp = Path(out.name)
        try:
            out.writelines(f"{link}\n" for link in links)
            out.close()
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)


def check(args, node):
    address = address_value(args.address if args.address is not None else node.uri.hostname)
    target = f"[{address}]:{node.port}" if ":" in address else f"{address}:{node.port}"
    result = probe(address, node, 1, args.timeout, ssl.create_default_context())
    if not result.successes:
        print(f"{target} 检查失败：{result.error}", file=sys.stderr)
        return 1
    print(f"{target} 通过 TCP、TLS 证书与 WebSocket 101 检查（{result.median_ms:.1f} ms）。")
    return 0


def test(args, node):
    ips = load_candidates(args)
    if not ips:
        raise ValueError("候选列表为空或与所选的 IP 版本不匹配")
    context = ssl.create_default_context()
    print(f"正在测试 {len(ips)} 个地址，每个地址握手 {args.attempts} 次。", flush=True)
    with ThreadPoolExecutor(max_workers=args.workers) as workers:
        results = sorted(workers.map(lambda ip: probe(ip, node, args.attempts, args.timeout, context), ips), key=rank)
    if args.download:
        for result in results[:args.download_top]:
            if result.successes:
                download(result, args, context)
        results.sort(key=rank)

    write_csv(args.csv, results, node, int(time.time()))
    print(f"测速结果：{args.csv}")
    usable = [result for result in results if result.successes]
    if not usable:
        print("没有地址通过 WebSocket 握手，请检查 CSV 中的错误。", file=sys.stderr)
        return 1
    print(f"通过 {len(usable)}/{len(results)}，首选 {usable[0].ip}，握手中位数 {usable[0].median_ms:.1f} ms。")
    if args.links:
        write_links(args.links, (node.link(result.ip) for result in usable[:args.count]))
        print(f"导入链接：{args.links}")
    return 0


def bounded(converter, low, high):
    def parse(value):
        number = converter(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"取值范围为 {low} 到 {high}")
        return number
    return parse


def interactive():
    print("chenniXvpn Cloudflare 自选与优选")
    print("使用面板中 VLESS 节点的原始链接。请在平时使用节点的网络中测速。")
    try:
        while True:
            print("\n1. 自选 IP 或域名\n2. 测速优选\n0. 退出")
            choice = input("请选择 [1/2/0]：").strip()
            if choice == "0":
                return 0
            if choice not in ("1", "2"):
                print("请输入 1、2 或 0。")
                continue
            try:
                node = Node.parse(input("粘贴原始 VLESS 链接："))
                if choice == "1":
                    address = address_value(input("输入自选 IP 或域名：").strip())
                    print(f"复制以下链接到客户端导入：\n{node.link(address)}")
                    continue
                family = input("Cloudflare 候选地址版本 [4/6，默认 4]：").strip() or "4"
                if family not in ("4", "6"):
                    raise ValueError("请选择 IPv4 或 IPv6。")
                filename = datetime.now().strftime("cf-results-%Y%m%d-%H%M%S-%f.csv")
                report = Path.home() / "chennixvpn" / filename
                args = argparse.Namespace(
                    candidates=None, family=int(family), sample=DEFAULT_SAMPLE,
                    attempts=DEFAULT_ATTEMPTS, workers=DEFAULT_WORKERS, timeout=DEFAULT_TIMEOUT,
                    download=False, csv=report, links=None,
                )
                if test(args, node) == 0:
                    print("在 VLESS 节点的 Cloudflare 页面导入该 CSV，然后选择一个握手成功的地址。")
            except (ValueError, OSError, http.client.HTTPException) as exc:
                print(f"错误：{exc}", file=sys.stderr)
    except EOFError:
        return 0
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130


def main():
    if len(sys.argv) == 1:
        return interactive()
    parser = argparse.ArgumentParser(
        description="从客户端检查 VLESS + WebSocket + TLS 节点，或测速和选择 Cloudflare IP。",
        epilog="不带参数运行可打开中文交互菜单。",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    public_check = commands.add_parser("check", help="从当前机器验证单个目标的 TCP、TLS 和 WebSocket")
    public_check.add_argument("--uri-file", type=Path, required=True)
    public_check.add_argument("--address", help="指定连接 IP 或域名，省略时使用节点地址")
    public_check.add_argument("--timeout", type=bounded(float, 0.5, 30), default=DEFAULT_TIMEOUT, help="连接和读取的超时秒数")
    select = commands.add_parser("select", help="用指定 IP 或域名生成链接")
    select.add_argument("--uri-file", type=Path, required=True)
    select.add_argument("--address", required=True, help="自选 IP 或域名")
    select.add_argument("--out", type=Path, required=True)
    speed = commands.add_parser("test", help="并发测试候选地址并输出 CSV")
    speed.add_argument("--uri-file", type=Path, required=True)
    speed.add_argument("--candidates", type=Path, help="每行一个 IP 或 CIDR。省略时使用 Cloudflare 官方网段")
    speed.add_argument("--family", type=int, choices=(4, 6), help="仅测指定 IP 版本，官方列表默认 IPv4")
    speed.add_argument("--sample", type=bounded(int, 1, 256), default=DEFAULT_SAMPLE)
    speed.add_argument("--attempts", type=bounded(int, 1, 10), default=DEFAULT_ATTEMPTS)
    speed.add_argument("--workers", type=bounded(int, 1, 32), default=DEFAULT_WORKERS)
    speed.add_argument("--timeout", type=bounded(float, 0.5, 30), default=DEFAULT_TIMEOUT, help="连接和读取的超时秒数")
    speed.add_argument("--download", action="store_true", help="下载测试走 Cloudflare 官方测速端点")
    speed.add_argument("--download-top", type=bounded(int, 1, 20), default=5)
    speed.add_argument("--download-bytes", type=bounded(int, 100_000, 10_000_000), default=1_000_000)
    speed.add_argument("--csv", type=Path, default=Path("output/cf-results.csv"))
    speed.add_argument("--links", type=Path, help="另存包含凭据的导入链接到新文件")
    speed.add_argument("--count", type=bounded(int, 1, 25), default=5, help="最多导出的链接数")
    args = parser.parse_args()
    try:
        node = Node.from_file(args.uri_file)
        if args.command == "check":
            return check(args, node)
        if args.command == "select":
            if args.uri_file.resolve() == args.out.resolve():
                raise ValueError("输出路径必须与原始链接文件不同")
            write_links(args.out, [node.link(address_value(args.address))])
            print(f"导入链接：{args.out}")
            return 0
        paths = [path.resolve() for path in (args.uri_file, args.candidates, args.csv, args.links) if path is not None]
        if len(set(paths)) != len(paths):
            raise ValueError("输入、CSV 和链接输出必须使用不同路径")
        if args.links and args.links.exists():
            raise ValueError("链接输出文件已存在，请指定新的 --links 路径")
        return test(args, node)
    except (ValueError, OSError, http.client.HTTPException) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
