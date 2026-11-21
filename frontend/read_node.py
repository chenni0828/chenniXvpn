#!/usr/bin/python3 -I
"""Fixed operations for the unprivileged panel service, installed root-owned."""
import hashlib
import json
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import nodes as node_manager


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=3, check=False,
                          errors="replace", env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})


def unit_state(unit):
    result = run("/usr/bin/systemctl", "show", "--value", "--property=ActiveState", unit)
    return result.stdout.strip() or "unknown"


def service_status(protocol):
    result = run("/usr/bin/systemctl", "show", "--property=LoadState,FragmentPath,ActiveState,UnitFileState,MainPID",
                 f"chennixvpn-{protocol}.service")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def deployment(protocol):
    unit = service_status(protocol)
    status = node_manager.inspect_node(protocol, unit)
    uri = node_manager.mappings(protocol, status["config"])[1] if status["installed"] else None
    return status, unit, uri


def certificate(path, now):
    if not path.is_file():
        return "missing", None
    try:
        result = run("/usr/bin/openssl", "x509", "-in", str(path), "-noout", "-dates")
        dates = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        start = ssl.cert_time_to_seconds(dates["notBefore"])
        expires = ssl.cert_time_to_seconds(dates["notAfter"])
    except (OSError, subprocess.TimeoutExpired, KeyError, ValueError):
        return "unknown", None
    if result.returncode:
        return "unknown", None
    return ("valid" if start <= now < expires else "invalid_dates"), expires


def socket_table():
    try:
        result = run("ss", "-H", "-lntup")
        return result.stdout.splitlines() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def listener(sockets, transport, port, owner):
    if sockets is None or port is None or owner is None:
        return "unknown"
    for line in sockets:
        fields = line.split(maxsplit=6)
        if len(fields) == 7 and fields[0] == transport and fields[4].rsplit(":", 1)[-1] == str(port):
            if owner.search(fields[6]):
                return "listening"
    return "missing"


def hy2_loaded_certificate(cert, pid):
    if not pid.isdigit() or int(pid) <= 0:
        return "unknown"
    running = Path("/proc") / pid / "root/run/credentials/chennixvpn-hy2.service/tls.crt"
    try:
        return "current" if running.read_bytes() == cert.read_bytes() else "different"
    except OSError:
        return "unknown"


def info(protocol, sockets, now):
    status, unit, raw = deployment(protocol)
    if not status["exists"]:
        return None
    installed = status["installed"]
    state = unit.get("ActiveState", "unknown")
    config = status["config"] or {}
    internal_port, public_port = config.get("internal"), config.get("port")
    cert = node_manager.LETSENCRYPT / "live" / config.get("cert", "") / "fullchain.pem"
    cert_status, expires = certificate(cert, now)
    pid = unit.get("MainPID", "")
    owner = re.compile(r"\bpid=" + pid + r"\b") if pid.isdigit() and int(pid) > 0 else None
    core = listener(sockets, "udp" if protocol == "hy2" else "tcp", internal_port, owner) if state == "active" else "unchecked"
    ingress = listener(sockets, "tcp", public_port, re.compile(r'\("nginx",')) if protocol == "vless" and state == "active" else "unchecked"
    loaded_cert = hy2_loaded_certificate(cert, pid) if protocol == "hy2" and state == "active" else "unchecked"
    installed_state = "installed" if installed else "incomplete"
    return dict(protocol=protocol, installed=installed, install_state=installed_state,
                state=state, enabled=unit.get("UnitFileState") == "enabled", boot_state=unit.get("UnitFileState"),
                domain=config.get("domain"), port=public_port, expires=expires, version=status["version"],
                can_repair=status["can_repair"], conflicts=status["conflicts"],
                email=config.get("email"), cloudflare=config.get("cloudflare", False), open_firewall=False,
                key=hashlib.sha256(raw.encode()).hexdigest() if installed else None,
                health=dict(checked_at=now, listener=core, ingress=ingress,
                            certificate=cert_status, loaded_certificate=loaded_cert))


def main(args):
    if args == ["status"]:
        sockets, now = socket_table(), time.time()
        nodes = [info(protocol, sockets, now) for protocol in ("hy2", "vless")]
        return {"nodes": [node for node in nodes if node],
                "timer": unit_state("certbot.timer"), "checked_at": now,
                "obsolete_certificates": node_manager.obsolete_certificates()}
    if len(args) != 2 or args[1] not in ("hy2", "vless"):
        raise ValueError("unknown operation")
    operation, protocol = args
    if operation == "share":
        _, unit, raw = deployment(protocol)
        return raw if unit.get("ActiveState") == "active" else None
    if operation == "logs":
        result = run("/usr/bin/journalctl", "--no-pager", "-o", "short-iso", "-u", f"chennixvpn-{protocol}.service", "-n", "60")
        if result.returncode:
            raise RuntimeError("journal unavailable")
        return result.stdout[-32768:]
    raise ValueError("unknown operation")


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:])))
