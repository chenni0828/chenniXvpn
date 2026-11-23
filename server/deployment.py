"""Install the project and manage its Linux services under a shared host lock."""

import hashlib
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

SERVER = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER))


ETC = Path("/etc/chennixvpn")
ADMIN = Path("/var/lib/chennixvpn-admin")
DATA = Path("/var/lib/chennixvpn")
BASE = Path("/opt/chennixvpn")
CURRENT = BASE / "current"
RUN = Path("/run/chennixvpn")
UNITS = Path("/etc/systemd/system")
NGINX = Path("/etc/nginx/conf.d")
LETSENCRYPT = Path("/etc/letsencrypt")
SYSCTL = Path("/etc/sysctl.d/99-chennixvpn.conf")
SYSCTL_CONFIG = """# Managed by chenniXvpn
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
"""
WEBROOT = ADMIN / "acme"
PANEL = "chennixvpn-panel.service"
TRAFFIC = "chennixvpn-traffic.service"
PANEL_REALM = 'Basic realm="chenniXvpn"'
VLESS_LOOPBACK = 18080
USER = "chennixvpn-panel"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}
QUIET = False


def run(*args, capture=False, check=True, timeout=45, cwd=None, env=None, stdin=None, stdout=None):
    capture = capture or (QUIET and stdout is None)
    result = subprocess.run(args, check=False, timeout=timeout, cwd=cwd, env=env or ENV, stdin=stdin,
                            stdout=subprocess.PIPE if capture else stdout,
                            stderr=subprocess.STDOUT if capture else None, text=True, errors="replace")
    if check and result.returncode:
        output = (result.stdout or "").strip()
        raise RuntimeError(f"{Path(args[0]).name} 失败（退出码 {result.returncode}）。" +
                           ("\n" + output[-1800:] if output else ""))
    return result


def system(*args, check=True, capture=False):
    return run("systemctl", *args, check=check, capture=capture)


def active(unit):
    return system("is-active", "--quiet", unit, check=False).returncode == 0


def enabled(unit):
    return system("is-enabled", "--quiet", unit, check=False, capture=True).returncode == 0


def validate_platform():
    if os.name != "posix" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise RuntimeError("请在运行 systemd 的 Linux 主机上以 root 身份执行。")
    if os.environ.get("CHENNIXVPN_PLATFORM_VALIDATED") == "1":
        return
    values = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    distro, version = (values.get(field, "").strip('"') for field in ("ID", "VERSION_ID"))
    minimum = {"debian": "12", "ubuntu": "22.04"}.get(distro)
    if not minimum or run("dpkg", "--compare-versions", version, "ge", minimum, check=False).returncode:
        raise RuntimeError("系统需要 Debian 12+ 或 Ubuntu 22.04+。")
    if platform.machine() not in ("x86_64", "aarch64"):
        raise RuntimeError("服务端支持 amd64 和 arm64。")
    os.environ["CHENNIXVPN_PLATFORM_VALIDATED"] = "1"


@contextmanager
def deployment_lock(read_only=False):
    import fcntl

    lock_path = RUN / "deploy.lock"
    if read_only:
        try:
            lock = lock_path.open("rb")
        except FileNotFoundError:
            yield
            return
        with lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            yield
        return
    RUN.mkdir(mode=0o755, exist_ok=True)
    with lock_path.open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def atomic_file(path, content, mode=0o600):
    if isinstance(content, str):
        content = content.encode()
    file = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".chennixvpn-", delete=False)
    candidate = Path(file.name)
    try:
        with file:
            candidate.chmod(mode)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        candidate.replace(path)
    finally:
        candidate.unlink(missing_ok=True)


class Backup:
    """Restore project-owned files and symlinks after a failed change."""

    def __init__(self, paths):
        self.files = {}
        for path in paths:
            if path.is_symlink():
                self.files[path] = ("symlink", path.readlink())
            elif path.is_file():
                self.files[path] = ("file", path.read_bytes(), path.stat().st_mode & 0o777)
            elif not path.exists():
                self.files[path] = ("absent",)
            else:
                raise RuntimeError(f"无法备份 {path}。")

    def restore(self):
        errors = []
        for path, (kind, *payload) in self.files.items():
            try:
                if kind == "file":
                    atomic_file(path, *payload)
                elif kind == "symlink":
                    set_symlink(path, payload[0])
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                errors.append(str(path))
        if errors:
            raise RuntimeError("自动恢复未完成，请检查 " + "、".join(errors) + "。")


def set_symlink(path, destination):
    candidate = path.with_name(f".{path.name}-{secrets.token_hex(5)}")
    try:
        candidate.symlink_to(destination)
        candidate.replace(path)
    finally:
        candidate.unlink(missing_ok=True)


def packages(*names):
    missing = []
    for name in names:
        result = run("dpkg-query", "-W", "-f=${Status}", name, check=False, capture=True)
        if result.stdout.strip() not in {"install ok installed", "hold ok installed"}:
            missing.append(name)
    if missing:
        options = ("-q", "-o", "Dpkg::Use-Pty=0", "-o", "Dpkg::Progress-Fancy=0") if QUIET else ()
        run("apt-get", *options, "update", timeout=300)
        run("apt-get", *options, "install", "-y", "--no-install-recommends", *missing, timeout=600)


def domain_value(value):
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if not isinstance(value, str):
        raise ValueError("请输入有效的 DNS 域名。")
    value = value.lower()
    if len(value) > 253 or not re.fullmatch(rf"(?:{label}\.)+{label}", value) or not re.search(r"[a-z]", value.rsplit(".", 1)[1]):
        raise ValueError("请输入有效的 DNS 域名。")
    return value


def email_value(value):
    if not isinstance(value, str) or len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value):
        raise ValueError("请输入用于签发证书的邮箱。")
    return value


def port_value(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("端口范围为 1–65535。")
    return value


def bandwidth_value(value):
    if value is None or value == 0:
        return 0
    if type(value) is not int or not 1 <= value <= 10000:
        raise ValueError("带宽范围为 1–10000 Mbps（0 表示不限制）。")
    return value


def apply_network_tuning():
    if read_text(SYSCTL) == SYSCTL_CONFIG.strip():
        return
    SYSCTL.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_file(SYSCTL, SYSCTL_CONFIG, 0o644)
    run("sysctl", "--system", check=False, capture=True)


def read_text(path, default=""):
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return default


def settings():
    data = read_text(ETC / "panel.json")
    return json.loads(data) if data else None


def trusted_file(path, private=False):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and (
        os.name != "posix" or (info.st_uid == os.geteuid() and not info.st_mode & (0o077 if private else 0o022)))


def node_cert_name(target, domain):
    return f"chennixvpn-{target}-" + hashlib.sha256(domain.encode()).hexdigest()[:16]


def node_config(target, pending=False):
    record = ETC / (f"{target}.state.pending" if pending else f"{target}.state")
    try:
        if not trusted_file(record, private=True) or record.stat().st_size > 4096:
            raise ValueError
        lines = record.read_text().splitlines()
        if len(lines) != 10:
            raise ValueError
        domain, internal, secret, path, public, email, cert, cloudflare, up_text, down_text = lines
        port = port_value(int(public))
        up_mbps = bandwidth_value(int(up_text))
        down_mbps = bandwidth_value(int(down_text))
        if (target == "vless" and (up_mbps or down_mbps)) or bool(up_mbps) != bool(down_mbps):
            raise ValueError
        valid_secret = r"[0-9a-f]{48}" if target == "hy2" else r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
        if (domain != domain_value(domain) or cert != node_cert_name(target, domain)
                or int(internal) != (port if target == "hy2" else VLESS_LOOPBACK)
                or not re.fullmatch(valid_secret, secret)
                or not re.fullmatch("" if target == "hy2" else r"/ws-[0-9a-f]{24}", path)
                or cloudflare not in ("true", "false")):
            raise ValueError
        return dict(domain=domain, internal=int(internal), secret=secret, path=path, port=port,
                    email=email_value(email), cert=cert, cloudflare=cloudflare == "true",
                    up_mbps=up_mbps, down_mbps=down_mbps)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise ValueError(f"节点状态文件无效：{record}") from None


def validate_new_domain(domain, target):
    panel = settings()
    if target != "panel" and panel and panel["domain"] == domain:
        raise ValueError("请使用不同于管理面板的域名。")
    for protocol in ("hy2", "vless"):
        if protocol != target:
            for pending in (False, True):
                configured = node_config(protocol, pending)
                if configured and configured["domain"] == domain:
                    raise ValueError("请为每种协议分别设置域名。")


def ipv6():
    return read_text(Path("/proc/sys/net/ipv6/conf/lo/disable_ipv6")) == "0"


def acme_site(domain):
    v6 = "listen [::]:80;" if ipv6() else ""
    return f"""server {{
    listen 80;
    {v6}
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{
        root {WEBROOT};
        default_type text/plain;
        try_files $uri =404;
    }}
    location / {{ return 404; }}
}}
"""


def tls_site(domain, port, cert, location, include_acme=True):
    lineage = LETSENCRYPT / "live" / cert
    v6 = f"listen [::]:{port} ssl;" if ipv6() else ""
    return (acme_site(domain) if include_acme else "") + f"""server {{
    listen {port} ssl;
    {v6}
    server_name {domain};
    ssl_certificate {lineage}/fullchain.pem;
    ssl_certificate_key {lineage}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:chennixvpn_tls:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
    tcp_nodelay on;
    client_max_body_size 2m;
    {location}
}}
"""


def reload_nginx(domain=None, start_if_inactive=True):
    status = run("nginx", "-t", capture=True)
    if domain and f'conflicting server name "{domain}"' in status.stdout:
        raise RuntimeError(f"Nginx 已配置同名站点 {domain}。")
    if active("nginx.service"):
        system("reload", "nginx.service")
    elif start_if_inactive:
        system("enable", "--now", "nginx.service")


def certificate_valid(domain, cert):
    path = LETSENCRYPT / "live" / cert
    fullchain, key = path / "fullchain.pem", path / "privkey.pem"
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(fullchain, key)
    except (OSError, ssl.SSLError):
        return False
    return run("openssl", "verify", "-untrusted", fullchain, "-verify_hostname", domain, fullchain,
               check=False, capture=True).returncode == 0


def local_http(port, path, domain=None, headers=None, *, verify_tls=True):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        if domain:
            raw = socket.create_connection(("127.0.0.1", port), timeout=3)
            try:
                context = ssl.create_default_context()
                if not verify_tls:
                    # Probe a retired local vhost even if its replacement presents another certificate.
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                connection.sock = context.wrap_socket(raw, server_hostname=domain)
            except Exception:
                raw.close()
                raise
        connection.request("GET", path, headers=headers or {})
        return connection.getresponse(), connection
    except Exception:
        connection.close()
        raise


def retry(check, message, attempts=12):
    for attempt in range(attempts):
        try:
            if check():
                return
        except (OSError, http.client.HTTPException):
            pass
        if attempt + 1 < attempts:
            time.sleep(1)
    raise RuntimeError(message)


def issue_certificate(domain, email, cert, previous_domain):
    site = NGINX / f"chennixvpn-challenge-{cert}.conf"
    if certificate_valid(domain, cert):
        if site.is_file():
            site.unlink()
            reload_nginx()
        return
    acme_directory = WEBROOT / ".well-known/acme-challenge"
    acme_directory.mkdir(parents=True, exist_ok=True)
    # Nginx workers need traverse access to the webroot parent only.
    ADMIN.chmod(0o711)
    for directory in (WEBROOT, acme_directory.parent, acme_directory):
        directory.chmod(0o755)
    probe = acme_directory / ("probe-" + secrets.token_hex(8))
    try:
        if previous_domain != domain:
            atomic_file(site, acme_site(domain), 0o644)
            reload_nginx(domain)
        elif not active("nginx.service"):
            reload_nginx(domain)
        atomic_file(probe, probe.name, 0o644)

        def check_probe():
            response, connection = local_http(80, f"/.well-known/acme-challenge/{probe.name}", headers={"Host": domain})
            with response:
                try:
                    return response.status == 200 and response.read(128).decode("ascii") == probe.name
                finally:
                    connection.close()

        retry(check_probe, "Nginx 未能提供 HTTP-01 验证文件，请检查 TCP 80。", attempts=5)
        run("certbot", "certonly", "--webroot", "-w", WEBROOT, "--cert-name", cert, "-d", domain,
            "--email", email, "--agree-tos", "--non-interactive", "--keep-until-expiring", timeout=130)
        if not certificate_valid(domain, cert):
            raise RuntimeError("证书、私钥或域名校验失败。")
    finally:
        probe.unlink(missing_ok=True)
        if site.is_file():
            site.unlink()
            reload_nginx()


def panel_origin(config):
    port = config["port"]
    return "https://" + config["domain"] + (f":{port}" if port != 443 else "")


def panel_site(config):
    port = config["local_port"]
    return tls_site(config["domain"], config["port"], config["cert"], f"""location / {{
        if ($http_host = "") {{ return 404; }}
        if ($host != {config["domain"]}) {{ return 404; }}
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }}""")


def loopback_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test:
        try:
            if os.name == "posix":
                # Match Gunicorn's bind behavior when a closed listener leaves TIME_WAIT sockets.
                test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def check_ingress(config, previous=None):
    has_ss = shutil.which("ss", path=ENV["PATH"])
    for port in (80, config["port"]):
        if has_ss:
            lines = run("ss", "-H", "-lnpt", "sport", "=", f":{port}", capture=True).stdout.splitlines()
            others = [line for line in lines if '("nginx",' not in line]
            if others and previous and previous["local_port"] == port and config["local_port"] != port:
                # The managed Gunicorn socket moves before Nginx claims this port.
                pid = system("show", "--property=MainPID", "--value", PANEL, capture=True).stdout.strip()
                if pid.isdecimal() and int(pid) > 0:
                    others = [line for line in others if f"pid={pid}," not in line]
            if others:
                raise ValueError(f"公网 TCP {port} 已由 Nginx 以外的程序占用。")
        else:
            # On minimal images iproute2 may first be installed in the apply phase.
            with socket.socket() as probe:
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError:
                    print(f"TCP {port} 已占用，安装 iproute2 后将复核监听进程。", file=sys.stderr)


def panel_service(config):
    origin = panel_origin(config)
    port = config["local_port"]
    return f"""[Unit]
Description=chenniXvpn administrative panel
After=network.target

[Service]
Type=exec
User={USER}
Group={USER}
WorkingDirectory={CURRENT}
StateDirectory=chennixvpn
StateDirectoryMode=0700
Environment=PANEL_DB={DATA}/panel.sqlite3
Environment=PANEL_ORIGIN={origin}
LoadCredential=auth:{ETC}/admin.hash
Environment=PANEL_AUTH=%d/auth
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/gunicorn --bind 127.0.0.1:{port} --workers 1 --threads 4 --timeout 60 frontend.panel:production()
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def traffic_service():
    return f"""[Unit]
Description=chenniXvpn network traffic accounting
After=network.target

[Service]
Type=exec
User={USER}
Group={USER}
WorkingDirectory={CURRENT}
StateDirectory=chennixvpn
StateDirectoryMode=0700
Environment=PANEL_DB={DATA}/panel.sqlite3
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m frontend.panel collect
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
"""


def sudo_rules():
    prefix = f"{USER} ALL=(root) NOPASSWD: /usr/bin/python3 -I"
    read_node = f"{CURRENT}/frontend/read_node.py"
    rules = [f'{prefix} {CURRENT}/server/operations.py',
             f"{prefix} {read_node} status"]
    for operation in ("logs", "share"):
        for protocol in ("hy2", "vless"):
            rules.append(f"{prefix} {read_node} {operation} {protocol}")
    return "\n".join(rules) + "\n"


def certificate_hooks():
    return """#!/bin/sh
case "$RENEWED_LINEAGE" in
    /etc/letsencrypt/live/chennixvpn-hy2-*)
        if grep -Fxq -- "${RENEWED_LINEAGE##*/}" /etc/chennixvpn/hy2.state; then
            systemctl try-restart chennixvpn-hy2.service
        fi
        ;;
    /etc/letsencrypt/live/chennixvpn-vless-*|/etc/letsencrypt/live/chennixvpn-panel-*)
        if systemctl is-active --quiet nginx.service; then
            nginx -t && systemctl reload nginx.service
        fi
        ;;
esac
"""


def renewal_hook():
    return LETSENCRYPT / "renewal-hooks/deploy/50-chennixvpn"


def renewal(activate=True):
    hook = renewal_hook()
    hook.parent.mkdir(parents=True, exist_ok=True)
    atomic_file(hook, certificate_hooks(), 0o755)
    if activate:
        system("enable", "--now", "certbot.timer")


def copy_project(source, destination):
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc", "preview.py", "output")
    for name in ("server", "frontend", "client"):
        if (source / name).is_symlink():
            raise RuntimeError("项目源码目录应为普通目录。")
        shutil.copytree(source / name, destination / name, ignore=ignored, symlinks=True)
    for name in ("install.sh", "VERSION"):
        if (source / name).is_symlink():
            raise RuntimeError("安装脚本和版本文件应为普通文件。")
        shutil.copyfile(source / name, destination / name)
    for path in destination.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise RuntimeError("项目源码包含链接或特殊文件。")
        path.chmod(0o755 if path.is_dir() else 0o644)


def panel_response(config, *, verify_tls=True):
    domain = config["domain"]
    port = config["port"]
    host = f"{domain}:{port}" if port != 443 else domain
    response, connection = local_http(port, "/api/nodes", domain, {"Host": host}, verify_tls=verify_tls)
    with response:
        try:
            return response.status, response.getheader("WWW-Authenticate", "")
        finally:
            connection.close()


def check_panel(config):
    status, challenge = panel_response(config)
    return status == 401 and challenge.startswith(PANEL_REALM)


def database_backup(action, helper, snapshot):
    command = ("/usr/bin/sudo", "-u", USER, "--", "/usr/bin/python3", "-I",
               helper, action, DATA / "panel.sqlite3")
    if action == "save":
        with snapshot.open("xb") as output:
            run(*command, stdout=output, timeout=300)
            output.flush()
            os.fsync(output.fileno())
    else:
        with snapshot.open("rb") as source:
            run(*command, stdin=source, timeout=300)


def restore_panel_services(states):
    for unit, (was_active, was_enabled) in reversed(list(states.items())):
        if enabled(unit) != was_enabled:
            system("enable" if was_enabled else "disable", unit)
        if was_active:
            system("reset-failed", unit, check=False)
            system("start", unit)
        elif active(unit):
            system("stop", unit)


def install_project_locked(source, config, *, admin_hash, provenance, previous=None):
    tag = read_text(source / "VERSION")
    fresh = admin_hash is not None
    print("正在检查并安装系统依赖。", file=sys.stderr, flush=True)
    had_ss = bool(shutil.which("ss", path=ENV["PATH"]))
    packages("python3", "gunicorn", "sudo", "ca-certificates", "openssl", "iproute2")
    if not had_ss and fresh:
        check_ingress(config, previous)
    packages("nginx", "certbot")
    if run("id", USER, check=False, capture=True).returncode:
        run("useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", USER)
    ETC.mkdir(mode=0o700, exist_ok=True)
    ADMIN.mkdir(mode=0o700, exist_ok=True)
    BASE.mkdir(mode=0o755, exist_ok=True)
    releases = BASE / "releases"
    releases.mkdir(mode=0o755, exist_ok=True)
    sudo_path = ETC.parent / "sudoers.d" / "chennixvpn"
    panel_path = ETC / "panel.json"
    auth = ETC / "admin.hash"
    site = NGINX / "chennixvpn-panel.conf"
    services = (PANEL, TRAFFIC)
    states = {unit: (active(unit), enabled(unit)) for unit in (*services, "nginx.service", "certbot.timer")}

    with tempfile.TemporaryDirectory(prefix="stage-", dir=releases) as temp:
        work = Path(temp)
        staged = work / "app"
        staged.mkdir()
        copy_project(source, staged)
        atomic_file(staged / "source.json", json.dumps(provenance), 0o644)
        candidate_auth = auth
        if fresh:
            candidate_auth = work / "admin.hash"
            atomic_file(candidate_auth, admin_hash + "\n")
        env = dict(ENV, PANEL_AUTH=str(candidate_auth), PANEL_DB=str(work / "preflight.db"),
                   PANEL_ORIGIN=panel_origin(config), PYTHONDONTWRITEBYTECODE="1")
        run("/usr/bin/gunicorn", "--check-config", "frontend.panel:production()", cwd=staged, env=env)
        candidate_rule = work / "sudoers"
        atomic_file(candidate_rule, sudo_rules(), 0o440)
        run("visudo", "-cf", candidate_rule)

        print("正在验证 HTTPS 证书。", file=sys.stderr, flush=True)
        previous_domain = previous.get("domain") if previous and site.is_file() else None
        issue_certificate(config["domain"], config["email"], config["cert"], previous_domain)
        destination = releases / f"{tag}-{secrets.token_hex(4)}"
        files = [CURRENT, auth, panel_path, sudo_path, site, renewal_hook(), SYSCTL,
                 *(UNITS / unit for unit in services)]
        backup = Backup(files)
        staged.rename(destination)
        recovery = None
        database_saved = changed = False
        helper = destination / "server/sqlite_backup.py"
        try:
            print("正在部署并检查面板和流量采集服务。", file=sys.stderr, flush=True)
            if not fresh:
                recovery = Path(tempfile.mkdtemp(prefix="rollback-", dir=ADMIN))
                for unit in services:
                    if states[unit][0]:
                        system("stop", unit)
                database_backup("save", helper, recovery / "panel.sqlite3")
                database_saved = True
            changed = True
            apply_network_tuning()
            if fresh:
                atomic_file(auth, candidate_auth.read_bytes())
            atomic_file(panel_path, json.dumps(config))
            atomic_file(sudo_path, candidate_rule.read_bytes(), 0o440)
            atomic_file(UNITS / PANEL, panel_service(config), 0o644)
            atomic_file(UNITS / TRAFFIC, traffic_service(), 0o644)
            set_symlink(CURRENT, destination)
            system("daemon-reload")
            atomic_file(site, panel_site(config), 0o644)
            reload_nginx(config["domain"], start_if_inactive=True)
            renewal(activate=True)
            if not fresh:
                import nodes

                nodes.sync_installed_nodes()
            run("/usr/bin/sudo", "-u", USER, "--", "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
                f"{CURRENT}/frontend/read_node.py", "status", capture=True)
            for unit in reversed(services):
                if fresh:
                    system("enable", "--now", unit)
                elif states[unit][0]:
                    system("start", unit)
            if fresh or states[TRAFFIC][0]:
                retry(lambda: active(TRAFFIC), "流量采集服务未启动。")
            if fresh or states[PANEL][0]:
                retry(lambda: check_panel(config), "面板未通过本机 HTTPS 认证检查。")
        except (Exception, KeyboardInterrupt) as original:
            try:
                if changed:
                    backup.restore()
                    run("sysctl", "--system", check=False, capture=True)
                    if database_saved:
                        database_backup("restore", helper, recovery / "panel.sqlite3")
                    system("daemon-reload")
                restore_panel_services(states)
                if states["nginx.service"][0]:
                    reload_nginx(start_if_inactive=False)
                if states[PANEL][0]:
                    retry(lambda: check_panel(previous or config), "旧版面板恢复后未通过认证检查。")
                if states[TRAFFIC][0]:
                    retry(lambda: active(TRAFFIC), "旧版采集服务恢复失败。")
            except Exception as restore_error:
                if recovery:
                    raise RuntimeError(f"升级失败且回滚未完成，恢复目录：{recovery}。"
                                       f"升级错误：{original}；回滚错误：{restore_error}") from restore_error
                raise
            if recovery:
                shutil.rmtree(recovery)
            shutil.rmtree(destination)
            raise
        if recovery:
            shutil.rmtree(recovery)


def run_package(source, upgrade=False, release_sha256=None):
    args = ["--upgrade"] if upgrade else []
    env = dict(ENV, CHENNIXVPN_PLATFORM_VALIDATED="1")
    if release_sha256:
        env["CHENNIXVPN_VERIFIED_ARCHIVE_SHA256"] = release_sha256
    run(sys.executable, "-IB", source / "server/deployment.py", *args, env=env, timeout=None, capture=upgrade)


if __name__ == "__main__":
    # Upgrade callers in installed releases depend on this script entry point.
    sys.modules["deployment"] = sys.modules[__name__]
    from installer import main

    sys.exit(main())
