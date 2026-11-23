"""Same-origin panel WSGI application. Production runs behind Gunicorn on Linux."""
import base64
import binascii
import csv
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation
from http import HTTPStatus
from pathlib import Path
from urllib.parse import quote

from client.cf_speedtest import Node, address_value
from frontend.diagnostics import diagnose_report, parse_report_with_metadata
from frontend.traffic import Store, collect, interfaces
from server.passwords import MAX_BASIC_AUTH_HEADER, read_admin_hash, verify_password
from server.releases import version_key

STATIC = Path(__file__).resolve().parent / "static"
PROJECT_DIR = Path(__file__).resolve().parents[1]
INSTALLED_DIR = Path("/opt/chennixvpn/current")
RELEASES = "https://github.com/chenni0828/chenniXvpn/releases"
MAX_BODY = 1024 * 1024
PROTOCOLS = ("hy2", "vless")
VLESS_ENTRIES = ("original", "preferred", "manual")
JOB_ID = re.compile(r"[0-9a-f]{32}")


class HttpError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def version_number(tag):
    try:
        return version_key(tag) if isinstance(tag, str) else ()
    except ValueError:
        return ()


class Host:
    hostname = socket.gethostname()
    preview = False

    def helper(self, script, *args, request=None, timeout=20):
        command = ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", str(INSTALLED_DIR / script), *args]
        try:
            payload = json.dumps(request).encode() if request is not None else None
            result = subprocess.run(command, input=payload, capture_output=True, timeout=timeout)
            if not result.stdout:
                raise ValueError(f"Helper returned no output (exit {result.returncode})")
            data = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            logging.exception("Panel helper failed: %s", script)
            raise HttpError(503, "服务器操作暂不可用，请查看面板服务日志") from None
        if isinstance(data, dict) and "error" in data:
            status = data.get("status", 503)
            raise HttpError(status if status in (400, 404, 409, 413, 503) else 503, data["error"])
        if result.returncode:
            raise HttpError(503, "服务器操作失败，请查看面板服务日志")
        return data

    def read(self, *args):
        return self.helper("frontend/read_node.py", *args)

    def operate(self, action, **parameters):
        return self.helper("server/operations.py", request={**parameters, "action": action},
                           timeout=45 if action == "versions" else 15)

    def interfaces(self):
        return interfaces()


class Panel:
    def __init__(self, store, host, origin, credential=None):
        self.store = store
        self.host = host
        self.origin = origin
        self.credential = credential
        self.auth_tag = None
        self.auth_key = secrets.token_bytes(32)
        self.version = (PROJECT_DIR / "VERSION").read_text(encoding="utf-8").strip()
        if not version_number(self.version):
            raise RuntimeError("Invalid project VERSION")
        release_download = f"{RELEASES}/download/{quote(self.version, safe='')}"
        self.downloads = {
            "windows": f"{release_download}/chennixvpn-cloudflare-windows-x64.exe",
            "linux": f"{release_download}/chennixvpn-cloudflare-linux.py",
        }

    def authorized(self, header):
        if self.credential is None:
            return self.host.preview
        # Cache only the keyed digest of the current valid header within this worker.
        if len(header) > MAX_BASIC_AUTH_HEADER or not header.startswith("Basic "):
            return False
        tag = hmac.digest(self.auth_key, header.encode("utf-8"), "sha256")
        if self.auth_tag and hmac.compare_digest(self.auth_tag, tag):
            return True
        try:
            user, password = base64.b64decode(header[6:], validate=True).decode().split(":", 1)
        except (ValueError, UnicodeError, binascii.Error):
            return False
        if user != "admin":
            return False
        if not verify_password(password, self.credential):
            return False
        self.auth_tag = tag
        return True

    def __call__(self, env, start):
        headers = [("Cache-Control","no-store"), ("X-Content-Type-Options","nosniff"),
                   ("Referrer-Policy","no-referrer"), ("Content-Security-Policy",
                   "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")]
        code = 200
        mime = "application/json; charset=utf-8"
        try:
            if not self.authorized(env.get("HTTP_AUTHORIZATION", "")):
                headers.append(("WWW-Authenticate", 'Basic realm="chenniXvpn", charset="UTF-8"'))
                raise HttpError(401, "请以管理员身份登录")
            path = env["PATH_INFO"]
            method = env["REQUEST_METHOD"]
            if method not in ("GET", "POST"):
                raise HttpError(405, "请求方式无效")
            if path.startswith("/api/"):
                body = {}
                if method == "POST":
                    if env.get("HTTP_ORIGIN") != self.origin:
                        raise HttpError(403, "请求来源不匹配")
                    if env.get("CONTENT_TYPE", "").split(";")[0] != "application/json":
                        raise HttpError(415, "需要 JSON 请求")
                    length = int(env.get("CONTENT_LENGTH") or 0)
                    if not 0 < length <= MAX_BODY:
                        raise HttpError(413, "请求为空或超过 1 MiB")
                    body = json.loads(env["wsgi.input"].read(length))
                    if not isinstance(body, dict):
                        raise ValueError("请求格式无效")
                data = self.api(method, path[5:], body)
                if method == "POST" and path == "/api/jobs":
                    code = 202
                output = json.dumps(data, ensure_ascii=False).encode()
            else:
                file = (STATIC / (path.lstrip("/") or "index.html")).resolve()
                if method != "GET" or not file.is_relative_to(STATIC) or not file.is_file():
                    raise HttpError(404, "页面不存在")
                mime = "text/javascript" if file.suffix == ".js" else mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                output = file.read_bytes()
        except HttpError as exc:
            code, output = exc.status, json.dumps({"error": str(exc)}).encode()
        except (ValueError, UnicodeError, csv.Error, InvalidOperation):
            code, output = 400, json.dumps({"error": "输入无效，请检查参数和 CSV 格式"}).encode()
        except Exception:
            logging.exception("Panel request failed")
            code, output = 503, json.dumps({"error": "读取失败，请查看面板服务日志"}).encode()
        start(f"{code} {HTTPStatus(code).phrase}", headers + [("Content-Type", mime), ("Content-Length", str(len(output)))])
        return [output]

    def api(self, method, path, body):
        parts = path.split("/")
        if method == "GET" and path == "traffic":
            return self.store.traffic(self.host.interfaces())
        if method == "GET" and path == "jobs":
            return self.host.operate("jobs")
        if method == "GET" and path == "installed-versions":
            return self.host.operate("installed-versions")
        if method == "GET" and len(parts) == 2 and parts[0] == "jobs" and JOB_ID.fullmatch(parts[1]):
            return self.host.operate("job", id=parts[1])
        if method == "POST" and path == "jobs":
            fields = {"operation", "target", "domain", "port", "email", "cloudflare",
                      "up_mbps", "down_mbps", "version", "cert", "release_id"}
            if not body.keys() <= fields:
                raise HttpError(400, "任务请求含有未知字段")
            return self.host.operate("start", **body)
        if method == "POST" and path == "updates/check":
            versions = self.host.operate("versions")
            for target in ("project", *PROTOCOLS):
                info = versions[target]
                installed = version_number(info["installed"])
                latest = version_number(info["latest"])
                info["available"] = bool(installed and latest > installed and not info["error"])
            return versions
        if method == "POST" and path == "settings":
            iface = body.get("iface")
            amount = Decimal(str(body.get("tb")))
            if iface not in ["", *self.host.interfaces()] or not amount.is_finite() or not Decimal(".001") <= amount <= 10000:
                raise HttpError(400, "请选择有效网卡，额度范围为 0.001 至 10000 TB")
            self.store.configure(iface, int(amount * 10**12))
            return {"ok": True}
        if method == "POST" and len(parts) == 3 and parts[:2] == ["settings", "entries"] and parts[2] in VLESS_ENTRIES:
            enabled = self.enabled_value(body)
            with self.store.db() as db:
                if enabled:
                    db.execute("DELETE FROM disabled_vless_entries WHERE kind=?", (parts[2],))
                else:
                    db.execute("INSERT OR IGNORE INTO disabled_vless_entries(kind) VALUES(?)", (parts[2],))
            return {"enabled": enabled}
        if method == "GET" and path == "nodes":
            result = self.host.read("status")
            for node in result["nodes"]:
                node["entries"] = {}
                node["latest"] = None
            vless = next((n for n in result["nodes"] if n["protocol"] == "vless"), None)
            kinds = []
            sharing_error = None
            try:
                with self.store.db() as db:
                    db.execute("BEGIN")
                    kinds = self.entry_kinds(db)
                    if vless and vless["key"]:
                        reports = self.reports(db, vless["key"], latest=True)
                        vless["latest"] = reports[0] if reports else None
                        if vless["state"] == "active":
                            entries = db.execute("SELECT kind,address FROM entries WHERE node=?", (vless["key"],))
                            vless["entries"] = {kind: address for kind, address in entries if kind in kinds}
            except sqlite3.Error:
                logging.exception("VLESS sharing state is unavailable")
                sharing_error = "VLESS 分享设置和报告暂不可用"
            return dict(**result, hostname=self.host.hostname, preview=self.host.preview, vless_entry_kinds=kinds,
                        sharing_error=sharing_error, project_version=self.version, downloads=self.downloads)
        if len(parts) == 3 and parts[0] == "nodes" and parts[1] in PROTOCOLS:
            protocol, action = parts[1:]
            if method == "GET" and action == "logs":
                return {"logs": self.host.read("logs", protocol)}
            if method == "POST" and action == "share":
                return self.share(protocol, body)
            if method == "POST" and protocol == "vless" and action == "speedtest-task":
                raw, key = self.raw(protocol)
                if body.get("key") != key:
                    raise HttpError(409, "节点已变更，请刷新后操作")
                return Node.parse(raw).speedtest_task().payload()
        if parts[0] == "reports":
            with self.store.db() as db:
                if method == "GET" and len(parts) == 1:
                    return self.reports(db)
                if method == "GET" and len(parts) == 2 and parts[1].isdigit():
                    row = db.execute("SELECT * FROM reports WHERE id=?", (parts[1],)).fetchone()
                    if not row:
                        raise HttpError(404, "报告不存在")
                    view = dict(row)
                    view["rows"] = json.loads(view.pop("rows_json"))
                    view["baseline"] = json.loads(view.pop("baseline_json") or "null")
                    view["diagnosis"] = diagnose_report(view["rows"], view["baseline"])
                    return view
                if method == "POST" and len(parts) == 3 and parts[1].isdigit() and parts[2] == "delete":
                    db.execute("DELETE FROM reports WHERE id=?", (parts[1],))
                    return {"ok": True}
                if method == "POST" and len(parts) == 1:
                    raw, key = self.raw("vless")
                    if body.get("key") != key:
                        raise HttpError(409, "节点已变更，请刷新后操作")
                    name, content = body.get("name"), body.get("csv")
                    if not isinstance(name,str) or not name.strip() or not isinstance(content,str):
                        raise HttpError(400, "请选择 CSV 文件")
                    try:
                        report = parse_report_with_metadata(content)
                    except (ValueError, csv.Error) as exc:
                        raise HttpError(400, str(exc)) from exc
                    if report.target_fingerprint != Node.parse(raw).target_fingerprint():
                        raise HttpError(409, "CSV 的测速目标与当前节点不一致，请重新测速")
                    rows = report.rows
                    usable = sum(r["successes"] > 0 for r in rows)
                    cur = db.execute("""INSERT INTO reports(node,name,ts,count,usable,best_ms,rows_json,measured_at,baseline_json)
                                     VALUES(?,?,?,?,?,?,?,?,?)""",
                                     (key, name.strip()[:120], time.time(), len(rows), usable,
                                      rows[0]["median_ms"] if usable else None, json.dumps(rows), report.measured_at,
                                      json.dumps(report.baseline)))
                    return {"id": cur.lastrowid}
        raise HttpError(404, "接口不存在")

    @staticmethod
    def enabled_value(body):
        if type(body.get("enabled")) is not bool:
            raise HttpError(400, "开关值须为 true 或 false")
        return body["enabled"]

    @staticmethod
    def entry_kinds(db):
        disabled = {row[0] for row in db.execute("SELECT kind FROM disabled_vless_entries")}
        return [kind for kind in VLESS_ENTRIES if kind not in disabled]

    @staticmethod
    def reports(db, key=None, latest=False):
        sql = "SELECT id,node,name,ts,count,usable,best_ms,measured_at FROM reports"
        if key is not None:
            sql += " WHERE node=?"
        sql += " ORDER BY id DESC"
        if latest:
            sql += " LIMIT 1"
        return [dict(r) for r in db.execute(sql, (key,) if key is not None else ())]

    def raw(self, protocol):
        raw = self.host.read("share", protocol)
        if not raw:
            raise HttpError(409, "请先安装该协议，并在设置中启用它")
        return raw, hashlib.sha256(raw.encode()).hexdigest()

    def share(self, protocol, body):
        raw, key = self.raw(protocol)
        if body.get("key") != key:
            raise HttpError(409, "节点已变更，请刷新后操作")
        kind = body.get("kind", "original")
        if kind not in VLESS_ENTRIES or (protocol != "vless" and kind != "original"):
            raise HttpError(400, "入口类型无效")
        if protocol != "vless":
            return {"uri": raw}
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE" if body.get("save") is True else "BEGIN")
            if kind not in self.entry_kinds(db):
                raise HttpError(409, "这个 VLESS 分享入口已关闭，可在设置中开启")
            if kind == "original":
                return {"uri": raw}
            if "address" in body:
                value = body["address"]
                if not isinstance(value,str) or not 0 < len(value) <= 253:
                    raise HttpError(400, "请输入有效的 IP 或域名")
                address = address_value(value.strip())
                if kind == "preferred":
                    report_id = body.get("report")
                    if type(report_id) is not int:
                        raise HttpError(400, "请选择有效报告")
                    row = db.execute("SELECT rows_json FROM reports WHERE node=? AND id=?", (key, report_id)).fetchone()
                    if not row:
                        raise HttpError(400, "请选择有效报告")
                    if not any(r["ip"] == address and r["successes"] for r in json.loads(row["rows_json"])):
                        raise HttpError(400, "请选择报告中握手成功的 IP")
            else:
                row = db.execute("SELECT address FROM entries WHERE node=? AND kind=?", (key, kind)).fetchone()
                if not row:
                    raise HttpError(404, "尚未保存这个入口")
                address = row[0]
            uri = Node.parse(raw).link(address)
            if body.get("save") is True:
                db.execute("INSERT OR REPLACE INTO entries VALUES(?,?,?)",(key, kind, address))
            return {"uri": uri, "address": address}


def production():
    credential = Path(os.environ["PANEL_AUTH"]).read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}:[0-9a-f]{64}", credential):
        raise RuntimeError("Invalid panel credential")
    return Panel(Store(os.environ["PANEL_DB"]), Host(), os.environ["PANEL_ORIGIN"], credential)


if __name__ == "__main__":
    if sys.argv[1:] == ["collect"]:
        collect(Store(os.environ["PANEL_DB"]))
    elif sys.argv[1:] == ["password"]:
        try:
            print(read_admin_hash())
        except ValueError as exc:
            sys.exit(str(exc))
    else:
        sys.exit("Expected collect or password")
