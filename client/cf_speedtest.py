#!/usr/bin/env python3
"""Select or benchmark Cloudflare addresses for an existing VLESS WebSocket node."""

import argparse
import base64
import csv
import hashlib
import http.client
import io
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DOWNLOAD_HOST = "speed.cloudflare.com"
CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
# Snapshot of https://www.cloudflare.com/ips-v4 for networks that cannot reach the API.
CLOUDFLARE_IPV4 = (
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
)
REPORT_VERSION = "1"
TASK_VERSION = 1
DEFAULT_SAMPLE = 24
DEFAULT_ATTEMPTS = 3
DEFAULT_WORKERS = 8
DEFAULT_TIMEOUT = 4
TCP_WORKERS = 200
TCP_ATTEMPTS = 4
TCP_TIMEOUT = 1
WS_SHORTLIST = 40
DOWNLOAD_TOP = 10
DOWNLOAD_TIMEOUT = 10
DOWNLOAD_BYTES = 99_999_999
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


def websocket_path(path):
    if not path.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("WebSocket 路径无效")
    return url.quote(path, safe="/%?=&:+@!$'()*,-.;_~[]")


def target_fingerprint(sni, host, port, path):
    target = json.dumps((sni, host, port, path), separators=(",", ":"))
    return hashlib.sha256(target.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class SpeedtestTask:
    original_address: str
    port: int
    sni: str
    host: str
    path: str

    def target_fingerprint(self):
        return target_fingerprint(self.sni, self.host, self.port, self.path)

    def payload(self):
        return dict(task_version=TASK_VERSION, original_address=self.original_address, port=self.port,
                    sni=self.sni, host=self.host, path=self.path, target_fingerprint=self.target_fingerprint())

    @classmethod
    def from_file(cls, path):
        with path.open("rb") as task_file:
            data = task_file.read(16385)
        if len(data) > 16384:
            raise ValueError("测速任务文件过大")
        try:
            payload = json.loads(data.decode("utf-8-sig"))
            if (not isinstance(payload, dict) or type(payload.get("task_version")) is not int
                    or payload["task_version"] != TASK_VERSION or type(payload.get("port")) is not int
                    or not 1 <= payload["port"] <= 65535):
                raise ValueError
            task = cls(address_value(payload["original_address"]), payload["port"], dns_name(payload["sni"]),
                       dns_name(payload["host"]), websocket_path(payload["path"]))
        except (ValueError, TypeError, AttributeError, KeyError):
            raise ValueError("测速任务格式无效，请从 Cloudflare 诊断页重新下载") from None
        if task.target_fingerprint() != payload.get("target_fingerprint"):
            raise ValueError("测速任务与目标指纹不匹配，请重新下载")
        return task


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
        path = websocket_path(params.get("path") or "/")
        port = parsed.port if parsed.port is not None else 443
        if not port:
            raise ValueError("端口必须在 1 到 65535 之间")
        return cls(parsed, params, port, sni, host, path)

    def target_fingerprint(self):
        return target_fingerprint(self.sni, self.host, self.port, self.path)

    def speedtest_task(self):
        return SpeedtestTask(address_value(self.uri.hostname), self.port, self.sni, self.host, self.path)

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


def cloudflare_networks(family, timeout):
    request = urllib.request.Request(CLOUDFLARE_IPS_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
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
    return networks


def load_candidates(args):
    sample = args.sample or DEFAULT_SAMPLE
    if args.candidates:
        source = args.candidates.read_text(encoding="utf-8-sig")
        return candidates(source, args.family, sample)
    family = args.family or 4
    return candidates("\n".join(cloudflare_networks(family, args.timeout)), family, sample)


def ipv4_subnet_samples(networks):
    blocks = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(network) for network in networks))
    if not 0 < sum(1 << max(0, 24 - block.prefixlen) for block in blocks) <= 20_000:
        raise ValueError("Cloudflare IPv4 网段超出预期规模")
    rng = random.SystemRandom()
    addresses = []
    for block in blocks:
        limit = max(block.prefixlen, 24)
        for subnet in block.subnets(new_prefix=limit):
            first = int(subnet.network_address)
            offset = rng.randrange(1, subnet.num_addresses - 1) if subnet.num_addresses > 2 else rng.randrange(subnet.num_addresses)
            addresses.append(str(ipaddress.IPv4Address(first + offset)))
    return addresses


def task_candidates(args):
    if args.candidates or args.sample is not None or args.family == 6:
        return load_candidates(args)
    try:
        return ipv4_subnet_samples(cloudflare_networks(4, args.timeout))
    except (OSError, ValueError, http.client.HTTPException):
        print("Cloudflare 网段接口暂不可用，使用内置的 IPv4 网段。", flush=True)
        return ipv4_subnet_samples(CLOUDFLARE_IPV4)


def remaining_time(deadline):
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise TimeoutError
    return remaining


class DeadlineReader(io.RawIOBase):
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        self.connection.settimeout(remaining_time(self.deadline))
        return self.connection.recv_into(buffer)

    def makefile(self, mode):
        return io.BufferedReader(self)


@contextmanager
def edge_response(ip, port, sni, host, path, headers, timeout, context):
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: chennixvpn-speedtest/1\r\n{headers}\r\n"
    deadline = time.perf_counter() + timeout
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        raise ProbeError(failure_message(exc, "TCP 连接")) from exc
    with raw:
        try:
            raw.settimeout(remaining_time(deadline))
            tls = context.wrap_socket(raw, server_hostname=sni)
        except OSError as exc:
            raise ProbeError(failure_message(exc, "TLS 握手")) from exc
        with tls:
            tls.settimeout(remaining_time(deadline))
            tls.sendall(request.encode("ascii"))
            with http.client.HTTPResponse(DeadlineReader(tls, deadline)) as response:
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


@dataclass
class TCPResult:
    ip: str
    attempts: int
    successes: int
    average_ms: float | None
    error: str


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


def tcp_probe(ip, port, attempts):
    timings = []
    error = ""
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
                timings.append((time.perf_counter() - start) * 1000)
        except OSError as exc:
            error = failure_message(exc, "TCP 连接")
    return TCPResult(ip, attempts, len(timings), statistics.mean(timings) if timings else None, error)


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


def download(result, size, timeout, context, *, timed_sample=False):
    # TCP port 443 belongs to Cloudflare's public benchmark endpoint.
    try:
        with edge_response(result.ip, 443, DOWNLOAD_HOST, DOWNLOAD_HOST, f"/__down?bytes={size}",
                           "Connection: close\r\nAccept-Encoding: identity\r\n", timeout, context) as response:
            if response.status != 200:
                raise ProbeError(f"HTTP {response.status}")
            start = time.perf_counter()
            received = 0
            try:
                while received < size:
                    chunk = response.read1(min(65536, size - received))
                    if not chunk:
                        raise ProbeError("下载响应短于请求大小")
                    received += len(chunk)
            except TimeoutError:
                if not timed_sample or not received:
                    raise
            result.mbps = received * 8 / max(time.perf_counter() - start, 0.000001) / 1_000_000
    except (OSError, http.client.HTTPException, ProbeError) as exc:
        result.download_error = failure_message(exc)


def rank_candidate(ip, attempts, successes, median_ms, download_mbps):
    latency = median_ms if median_ms is not None else float("inf")
    return -successes / attempts, download_mbps is None, -(download_mbps or 0), latency, ip


def rank(result):
    return rank_candidate(result.ip, result.attempts, result.successes, result.median_ms, result.mbps)


@contextmanager
def output_file(path, encoding, newline):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, encoding=encoding, newline=newline, delete=False, mode="w") as out:
        temp = Path(out.name)
        try:
            yield out
            out.close()
            temp.replace(path)
        finally:
            out.close()
            temp.unlink(missing_ok=True)


def write_csv(path, results, node, measured_at, baseline=None):
    metadata = (REPORT_VERSION, node.target_fingerprint(), measured_at)
    columns = ["rank", "ip", "attempts", "successes", "failure_pct", "median_ms", "download_mbps",
               "error", "download_error", "report_version", "target_fingerprint", "measured_at"]
    comparison = ()
    if baseline is not None:
        columns.extend(("baseline_attempts", "baseline_successes", "baseline_median_ms", "baseline_error"))
        comparison = (baseline.attempts, baseline.successes, baseline.median_ms, baseline.error)
    with output_file(path, "utf-8-sig", "") as out:
        rows = csv.writer(out)
        rows.writerow(columns)
        for number, result in enumerate(results, 1):
            rows.writerow([
                number, result.ip, result.attempts, result.successes,
                f"{100 * (1 - result.successes / result.attempts):.1f}",
                result.median_ms, result.mbps, result.error, result.download_error, *metadata, *comparison,
            ])


def write_links(path, links):
    with output_file(path, "utf-8", "\n") as out:
        out.writelines(f"{link}\n" for link in links)


def windows_executable_dir():
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


def output_path(path):
    directory = windows_executable_dir()
    if directory is None:
        return path
    resolved = (directory / path).resolve()
    if resolved.parent != directory:
        raise ValueError("生成的文件必须保存在 EXE 所在目录")
    return resolved


def task_output_dir():
    executable_dir = windows_executable_dir()
    directory = executable_dir or Path.cwd()
    try:
        with tempfile.NamedTemporaryFile(dir=directory):
            pass
    except OSError as exc:
        hint = "请将 EXE 移入可写目录" if executable_dir else "请从可写目录运行脚本"
        raise ValueError(f"无法在 {directory} 保存测速结果。{hint}。") from exc
    return directory


def measure_many(addresses, workers, measure, label):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = [pool.submit(measure, address) for address in addresses]
        try:
            for index, future in enumerate(as_completed(pending), 1):
                results.append(future.result())
                if index == len(pending) or index % workers == 0:
                    print(f"{label} {index}/{len(pending)}", flush=True)
        except KeyboardInterrupt:
            for future in pending:
                future.cancel()
            raise
    return results


def test_task(args, task):
    directory = task_output_dir()
    addresses = task_candidates(args)
    if not addresses:
        raise ValueError("候选列表为空或与所选的 IP 版本不匹配")
    started = datetime.now()
    run_name = f"cf-{started:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:12]}"
    report_file = directory / (run_name + "-report.csv")

    print(f"TCP 初筛 {len(addresses)} 个地址，每个地址连接 {args.attempts} 次，{args.workers} 并发。", flush=True)
    tcp_results = measure_many(addresses, args.workers, lambda ip: tcp_probe(ip, task.port, args.attempts), "TCP 初筛")
    tcp_results.sort(key=lambda r: (-r.successes, r.average_ms if r.average_ms is not None else float("inf"), r.ip))

    shortlist = [r.ip for r in tcp_results[:WS_SHORTLIST] if r.successes]
    if not shortlist:
        print("没有地址通过 TCP 初筛，请检查网络和节点端口后重试。", file=sys.stderr)
        return 1
    context = ssl.create_default_context()
    print(f"复测原始入口和 {len(shortlist)} 个候选。", flush=True)
    baseline = probe(task.original_address, task, args.attempts, args.timeout, context)
    results = measure_many(shortlist, DEFAULT_WORKERS,
                           lambda ip: probe(ip, task, args.attempts, args.timeout, context), "节点握手")
    results.sort(key=rank)
    usable = [r for r in results if r.successes]
    download_queue = usable[:args.download_top]
    for index, result in enumerate(download_queue, 1):
        print(f"Cloudflare 边缘下载 {index}/{len(download_queue)} · {result.ip}", flush=True)
        download(result, args.download_bytes, DOWNLOAD_TIMEOUT, context, timed_sample=True)
    results.sort(key=rank)
    write_csv(report_file, results, task, int(time.time()), baseline)
    print(f"面板导入报告：{report_file}", flush=True)
    if not usable:
        print("候选均未完成 WebSocket 握手，可导入报告查看失败原因。", file=sys.stderr)
        return 1
    best = results[0]
    print(f"{len(usable)}/{len(results)} 个候选通过握手，首选 {best.ip} · {best.successes}/{best.attempts} 次成功。")
    return 0


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
                download(result, args.download_bytes, args.timeout, context)
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


def choose_windows_task():
    import ctypes
    from ctypes import wintypes as win

    # OPENFILENAMEW includes unused fields to preserve the native structure layout.
    class OpenFileName(ctypes.Structure):
        _fields_ = [
            ("size", win.DWORD), ("owner", win.HWND), ("instance", win.HINSTANCE),
            ("filter", win.LPCWSTR), ("custom_filter", win.LPWSTR), ("custom_filter_size", win.DWORD),
            ("filter_index", win.DWORD), ("file", win.LPWSTR), ("max_file", win.DWORD),
            ("file_title", win.LPWSTR), ("max_file_title", win.DWORD), ("initial_dir", win.LPCWSTR),
            ("title", win.LPCWSTR), ("flags", win.DWORD), ("file_offset", win.WORD),
            ("extension_offset", win.WORD), ("default_extension", win.LPCWSTR),
            ("custom_data", win.LPARAM), ("hook", ctypes.c_void_p), ("template_name", win.LPCWSTR),
            ("reserved", ctypes.c_void_p), ("reserved_size", win.DWORD), ("flags_ex", win.DWORD),
        ]

    filename = ctypes.create_unicode_buffer(32768)
    options = OpenFileName(size=ctypes.sizeof(OpenFileName), filter="测速任务 (*.json)\0*.json\0\0",
                           file=ctypes.cast(filename, win.LPWSTR), max_file=len(filename),
                           title="选择 chenniXvpn 测速任务", default_extension="json")
    options.flags = 0x00080000 | 0x00001000 | 0x00000800 | 0x00000008  # Explorer, existing file/path, keep cwd
    dialog = ctypes.WinDLL("comdlg32.dll", winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    open_file = dialog.GetOpenFileNameW
    open_file.argtypes = (ctypes.POINTER(OpenFileName),)
    open_file.restype = win.BOOL
    if open_file(ctypes.byref(options)):
        return filename.value
    error = dialog.CommDlgExtendedError()
    if error:
        raise OSError(f"打开任务文件选择器失败（{error:#x}）")
    return None


def desktop(task_path=None):
    try:
        task_path = task_path if task_path is not None else choose_windows_task()
        if not task_path:
            return 0
        status = main(["test", "--task", task_path])
    except OSError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        status = 2
    print("\n按回车退出。", flush=True)
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    return status


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return desktop() if windows_executable_dir() else interactive()
    if windows_executable_dir() and len(argv) == 1 and Path(argv[0]).suffix.lower() == ".json":
        return desktop(argv[0])
    parser = argparse.ArgumentParser(
        description="从客户端检查 VLESS + WebSocket + TLS 节点，或测速和选择 Cloudflare IP。",
        epilog="使用 test --task 运行 Cloudflare 诊断页导出的任务。",
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
    source = speed.add_mutually_exclusive_group(required=True)
    source.add_argument("--task", type=Path, help="Cloudflare 诊断页导出的 JSON 测速任务")
    source.add_argument("--uri-file", type=Path, help="读取原始 VLESS 链接，使用原有测速模式")
    speed.add_argument("--candidates", type=Path, help="每行一个 IP 或 CIDR。省略时使用 Cloudflare 官方网段")
    speed.add_argument("--family", type=int, choices=(4, 6), help="仅测指定 IP 版本，官方列表默认 IPv4")
    speed.add_argument("--sample", type=bounded(int, 1, 256), help="限制抽样数，省略时任务模式按 IPv4 /24 抽样")
    speed.add_argument("--attempts", type=bounded(int, 1, 10))
    speed.add_argument("--workers", type=bounded(int, 1, TCP_WORKERS))
    speed.add_argument("--timeout", type=bounded(float, 0.5, 30), default=DEFAULT_TIMEOUT, help="连接和读取的超时秒数")
    speed.add_argument("--download", action="store_true", help="原始链接模式下启用 Cloudflare 边缘下载测速")
    speed.add_argument("--download-top", type=bounded(int, 1, 20), help="任务模式最多测速 10 个候选")
    speed.add_argument("--download-bytes", type=bounded(int, 100_000, DOWNLOAD_BYTES))
    speed.add_argument("--csv", type=Path, help="原始链接模式的 CSV 输出路径")
    speed.add_argument("--links", type=Path, help="另存包含凭据的导入链接到新文件")
    speed.add_argument("--count", type=bounded(int, 1, 25), default=5, help="最多导出的链接数")
    args = parser.parse_args(argv)
    try:
        if args.command == "test" and args.task:
            if args.csv is not None or args.links is not None:
                raise ValueError("任务模式会生成带时间戳的 CSV，节点分享链接请在面板预览")
            args.attempts = args.attempts or TCP_ATTEMPTS
            args.workers = args.workers or TCP_WORKERS
            args.download_top = min(args.download_top or DOWNLOAD_TOP, DOWNLOAD_TOP)
            args.download_bytes = args.download_bytes or DOWNLOAD_BYTES
            return test_task(args, SpeedtestTask.from_file(args.task))
        node = Node.from_file(args.uri_file)
        if args.command == "check":
            return check(args, node)
        if args.command == "select":
            args.out = output_path(args.out)
            if args.uri_file.resolve() == args.out.resolve():
                raise ValueError("输出路径必须与原始链接文件不同")
            write_links(args.out, [node.link(address_value(args.address))])
            print(f"导入链接：{args.out}")
            return 0
        args.attempts = args.attempts or DEFAULT_ATTEMPTS
        args.workers = args.workers or DEFAULT_WORKERS
        args.download_top = args.download_top or 5
        args.download_bytes = args.download_bytes or 1_000_000
        default_csv = "cf-results.csv" if windows_executable_dir() else "output/cf-results.csv"
        args.csv = output_path(args.csv or Path(default_csv))
        if args.links:
            args.links = output_path(args.links)
        paths = [path.resolve() for path in (args.uri_file, args.candidates, args.csv, args.links) if path is not None]
        if len(set(paths)) != len(paths):
            raise ValueError("输入、CSV 和链接输出必须使用不同路径")
        if args.links and args.links.exists():
            raise ValueError("链接输出文件已存在，请指定新的 --links 路径")
        return test(args, node)
    except (ValueError, OSError, http.client.HTTPException) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
