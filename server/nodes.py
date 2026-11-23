"""Configure and update the two supported protocols."""

import filecmp
import json
import re
import secrets
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlencode

from deployment import (ADMIN, ETC, LETSENCRYPT, NGINX, SYSCTL, UNITS, VLESS_LOOPBACK, Backup, acme_site,
                        active, apply_network_tuning, atomic_file, bandwidth_value, domain_value, email_value,
                        enabled, issue_certificate, local_http, node_cert_name, node_config, packages, port_value,
                        read_text, reload_nginx, renewal, retry, run, settings, system, tls_site, trusted_file,
                        validate_new_domain)
from releases import core_asset, download_asset, release, version_key


BIN = Path("/usr/local/lib/chennixvpn")
CLOUDFLARE_PORTS = {443, 2053, 2083, 2087, 2096, 8443}


def unit_name(target):
    return f"chennixvpn-{target}.service"


def core_paths(target):
    return (BIN / ("hysteria" if target == "hy2" else "xray"),
            ETC / ("hy2.yaml" if target == "hy2" else "vless.json"),
            ETC / f"{target}.version")


def port_sockets(port, transport):
    return run("ss", "-H", f"-lnp{transport}", "sport", "=", f":{port}", capture=True).stdout


def validate_options(target, fields):
    domain = domain_value(fields.get("domain"))
    port = port_value(fields.get("port"))
    email = email_value(fields.get("email"))
    cloudflare = fields.get("cloudflare", False)
    open_firewall = fields.get("open_firewall", False)
    up_mbps = bandwidth_value(fields.get("up_mbps", 0))
    down_mbps = bandwidth_value(fields.get("down_mbps", 0))
    if type(cloudflare) is not bool or type(open_firewall) is not bool:
        raise ValueError("无效的节点选项。")
    if open_firewall:
        raise ValueError("请在 VPS 防火墙和云安全组中放行所需端口。")
    if target == "hy2" and cloudflare:
        raise ValueError("Hysteria 2 使用直连 UDP。请将节点域名设为仅 DNS。")
    if target == "hy2" and bool(up_mbps) != bool(down_mbps):
        raise ValueError("配置 Hysteria 2 Brutal 带宽时，需同时填写上行和下行带宽。")
    if target == "vless":
        if up_mbps or down_mbps:
            raise ValueError("VLESS 节点不支持带宽限制参数。")
        if port in {80, VLESS_LOOPBACK}:
            raise ValueError("这个 TCP 端口已预留给 HTTP 验证或本机核心。")
        if cloudflare and port not in CLOUDFLARE_PORTS:
            raise ValueError("Cloudflare HTTPS 代理仅支持 TCP 443、2053、2083、2087、2096、8443。")
    return dict(domain=domain, port=port, email=email, cloudflare=cloudflare, open_firewall=open_firewall,
                up_mbps=up_mbps, down_mbps=down_mbps)


def _vless_core(internal, secret, path):
    core = dict(
        log=dict(loglevel="warning"),
        inbounds=[dict(listen="127.0.0.1", port=internal, protocol="vless",
                       settings=dict(clients=[dict(id=secret)], decryption="none"),
                       streamSettings=dict(network="ws", wsSettings=dict(path=path)))],
        outbounds=[dict(protocol="freedom")],
    )
    return json.dumps(core, indent=2)


def legacy_mappings(target, config):
    """Frozen v0.1.0-v0.1.3 output snapshot for upgrade conflict checks and key migration; keep covered by tests."""
    internal, port = config["internal"], config["port"]
    domain, secret, path = (config[name] for name in ("domain", "secret", "path"))
    unit = unit_name(target)
    if target == "hy2":
        return (
            f"""listen: ":{internal}"
tls:
  cert: /run/credentials/{unit}/tls.crt
  key: /run/credentials/{unit}/tls.key
auth:
  type: password
  password: "{secret}"
""",
            f"hysteria2://{secret}@{domain}:{port}/?sni={domain}#chenniXvpn-HY2",
            acme_site(domain),
        )
    query = urlencode(dict(encryption="none", security="tls", sni=domain, type="ws", host=domain, path=path))
    site = tls_site(domain, port, config["cert"], f"""location = {path} {{
        proxy_pass http://127.0.0.1:{internal};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }}
    location / {{ return 404; }}""")
    return _vless_core(internal, secret, path), f"vless://{secret}@{domain}:{port}?{query}#chenniXvpn-VLESS", site


def mappings(target, config):
    internal, port = config["internal"], config["port"]
    domain, secret, path = (config[name] for name in ("domain", "secret", "path"))
    unit = unit_name(target)
    if target == "hy2":
        up_mbps, down_mbps = config.get("up_mbps", 0), config.get("down_mbps", 0)
        bandwidth_yaml = f"bandwidth:\n  up: {up_mbps} mbps\n  down: {down_mbps} mbps\n" if up_mbps and down_mbps else ""
        return (
            f"""listen: ":{internal}"
tls:
  cert: /run/credentials/{unit}/tls.crt
  key: /run/credentials/{unit}/tls.key
auth:
  type: password
  password: "{secret}"
{bandwidth_yaml}masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:80
    rewriteHost: true
""",
            f"hysteria2://{secret}@{domain}:{port}/?sni={domain}#chenniXvpn-HY2",
            acme_site(domain),
        )
    query = urlencode(dict(encryption="none", security="tls", sni=domain, alpn="http/1.1", fp="chrome",
                           type="ws", host=domain, path=f"{path}?ed=2048"))
    site = tls_site(domain, port, config["cert"], f"""location = {path} {{
        if ($http_upgrade !~* "^websocket$") {{ return 404; }}
        proxy_pass http://127.0.0.1:{internal};
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }}
    location / {{ return 404; }}""")
    return _vless_core(internal, secret, path), f"vless://{secret}@{domain}:{port}?{query}#chenniXvpn-VLESS", site


def core_service(target, binary, path, cert):
    if target == "hy2":
        lineage = LETSENCRYPT / "live" / cert
        command = f"""CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LoadCredential=config.yaml:{path}
LoadCredential=tls.crt:{lineage}/fullchain.pem
LoadCredential=tls.key:{lineage}/privkey.pem
ExecStart={binary} server -c %d/config.yaml"""
    else:
        command = f"""CapabilityBoundingSet=
LoadCredential=config.json:{path}
ExecStart={binary} run -config %d/config.json"""
    return f"""[Unit]
Description=chenniXvpn {target.upper()} node
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
DynamicUser=yes
NoNewPrivileges=yes
{command}
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
"""


def check_candidate(target, binary, config):
    command = ("version",) if target == "hy2" else ("run", "-test", "-config", config)
    run(binary, *command, timeout=15, capture=True)


def acquire_core(target, work, tag=None):
    data = release(target, tag)
    if target == "hy2":
        binary = work / "hysteria"
        download_asset(data, core_asset(target), binary)
    else:
        binary = work / "xray"
        archive = work / "xray.zip"
        download_asset(data, core_asset(target), archive)
        with zipfile.ZipFile(archive) as files:
            entry = files.getinfo("xray")
            if not 0 < entry.file_size <= 120 * 1024**2:
                raise RuntimeError("Xray 二进制文件大小异常。")
            with files.open(entry) as source, binary.open("xb") as output:
                shutil.copyfileobj(source, output)
    binary.chmod(0o755)
    return binary, data["tag_name"]


def healthy(target, config):
    name = unit_name(target)
    if not active(name):
        return False
    pid = system("show", "-p", "MainPID", "--value", name, capture=True).stdout.strip()
    transport = "u" if target == "hy2" else "t"
    if pid in {"", "0"} or f"pid={pid}," not in port_sockets(config["internal"], transport):
        return False
    if target == "hy2":
        return True
    domain = config["domain"]
    response, connection = local_http(config["port"], config["path"], domain,
                                      {"Host": domain, "Upgrade": "websocket", "Connection": "Upgrade",
                                       "Sec-WebSocket-Version": "13",
                                       "Sec-WebSocket-Key": "MDEyMzQ1Njc4OWFiY2RlZg=="})
    with response:
        try:
            return response.status == 101
        finally:
            connection.close()


def prior_service(name, was_active, was_enabled):
    if was_enabled:
        system("enable", name)
    else:
        system("disable", name, check=False)
    if was_active:
        system("reset-failed", name, check=False)
        system("start", name)


def node_paths(target):
    binary, core, version = core_paths(target)
    return dict(binary=binary, core=core, version=version, site=NGINX / f"chennixvpn-{target}.conf",
                state=ETC / f"{target}.state", pending=ETC / f"{target}.state.pending",
                uri=ETC / f"{target}.uri", unit=UNITS / unit_name(target))


def obsolete_certificates():
    panel = settings() or {}
    configured = {panel["cert"]} if panel.get("cert") else set()
    for target in ("hy2", "vless"):
        for pending in (False, True):
            try:
                config = node_config(target, pending)
            except ValueError:
                return []
            if config:
                configured.add(config["cert"])
    try:
        names = {path.name for path in (LETSENCRYPT / "live").iterdir() if path.is_dir()}
    except OSError:
        return []
    return sorted(name for name in names
                  if re.fullmatch(r"chennixvpn-(?:panel-[0-9a-f]{16}|(?:hy2|vless)-?[0-9a-f]*)", name)
                  and name not in configured)


def retire_certificate(cert):
    if not isinstance(cert, str) or cert not in obsolete_certificates():
        raise ValueError("该证书不存在或仍被现有服务引用。")
    run("certbot", "delete", "--cert-name", cert, "--non-interactive", timeout=60)
    return f"已清理旧证书 {cert}。"


def inspect_node(target, unit):
    """Compare the fixed managed paths with the saved intent, without running a core."""
    paths = node_paths(target)
    present = {key for key, path in paths.items() if path.is_symlink() or path.exists()}
    conflicts = {paths[key] for key in present
                 if not trusted_file(paths[key], private=key in {"state", "pending", "uri", "core"})}
    fragment = unit.get("FragmentPath")
    if fragment and Path(fragment) != paths["unit"]:
        conflicts.add(Path(fragment))
    records = present & {"state", "pending"}
    config = tag = None
    if len(records) != 1:
        conflicts.update(paths[key] for key in present)
    elif not conflicts:
        record = next(iter(records))
        try:
            config = node_config(target, pending=record == "pending")
            validate_options(target, config)
        except (ValueError, TypeError):
            conflicts.add(paths[record])
            config = None
    if config:
        core, share, site = mappings(target, config)
        legacy_core, legacy_share, legacy_site = legacy_mappings(target, config)
        expected = dict(core=core, uri=share + "\n", site=site,
                        unit=core_service(target, paths["binary"], paths["core"], config["cert"]))
        legacy = dict(core=legacy_core, uri=legacy_share + "\n", site=legacy_site, unit=expected["unit"])
        for key, content in expected.items():
            if key in present and paths[key].read_bytes() not in {content.encode(), legacy[key].encode()}:
                conflicts.add(paths[key])
        if "version" in present:
            tag = read_text(paths["version"])
            try:
                version_key(tag)
            except ValueError:
                conflicts.add(paths["version"])
                tag = None
    installed = (not conflicts and present == set(paths) - {"pending"} and unit.get("LoadState") == "loaded")
    return dict(config=config, version=tag, installed=installed, exists=bool(present or fragment or conflicts),
                pending=bool(config and paths["pending"].exists()),
                can_repair=bool(config and not conflicts and not installed),
                conflicts=sorted(str(path) for path in conflicts))


def node_unit(target):
    result = system("show", "-p", "LoadState", "-p", "FragmentPath", unit_name(target),
                    check=False, capture=True)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def configure(operation, target, fields):
    status = inspect_node(target, node_unit(target))
    if status["conflicts"]:
        raise ValueError("请检查冲突文件：" + "、".join(status["conflicts"]))
    fresh, repairing = operation == "create", operation == "repair"
    if fresh and status["exists"]:
        raise ValueError("该节点已存在。" if status["installed"] else "请先恢复未完成的节点安装。")
    if repairing and not status["can_repair"]:
        raise ValueError("没有可恢复的节点安装。")
    if operation == "configure" and not status["installed"]:
        raise ValueError("请先创建或恢复节点。")
    previous = status["config"]
    options = validate_options(target, previous if repairing else fields)
    panel = settings()
    if not panel:
        raise RuntimeError("请先安装管理面板。")
    domain, port = options["domain"], options["port"]
    validate_new_domain(domain, target)
    config = (previous or {}) | options
    config["internal"] = config["port"] if target == "hy2" else VLESS_LOOPBACK
    config["cert"] = node_cert_name(target, domain)
    if fresh:
        config["secret"] = secrets.token_hex(24) if target == "hy2" else str(uuid.uuid4())
        config["path"] = "" if target == "hy2" else "/ws-" + secrets.token_hex(12)

    name = unit_name(target)
    was_active, was_enabled = active(name), enabled(name)
    transport = "u" if target == "hy2" else "t"
    if not (was_active and previous and previous["internal"] == config["internal"]):
        if port_sockets(config["internal"], transport):
            raise ValueError(f"协议本机端口 {config['internal']} 已被占用。")
    if target == "vless":
        if port == panel["local_port"]:
            raise ValueError("公网端口不能与面板本机端口相同。")
        listeners = port_sockets(port, "t")
        if listeners and any('("nginx",' not in line for line in listeners.splitlines()):
            raise ValueError(f"公网 TCP {port} 已被其他程序占用。")

    packages("nginx", "certbot")
    BIN.mkdir(parents=True, exist_ok=True)
    paths = node_paths(target)
    binary, core, version = core_paths(target)
    site, state, pending = (paths[key] for key in ("site", "state", "pending"))
    wire_config, share, site_config = mappings(target, config)
    changed = "\n".join(str(config[key]) if type(config[key]) is not bool else str(config[key]).lower()
                        for key in ("domain", "internal", "secret", "path", "port", "email", "cert",
                                    "cloudflare", "open_firewall", "up_mbps", "down_mbps")) + "\n"

    with tempfile.TemporaryDirectory(prefix="node-", dir=ADMIN) as temp:
        work = Path(temp)
        if fresh or repairing:
            candidate, tag = acquire_core(target, work, status["version"])
            if (not status["pending"] and binary.exists()
                    and not filecmp.cmp(binary, candidate, shallow=False)):
                raise ValueError(f"核心文件与已校验的发行版不一致：{binary}")
        else:
            candidate, tag = binary, status["version"]
        candidate_config = work / core.name
        atomic_file(candidate_config, wire_config)
        check_candidate(target, candidate, candidate_config)
        backup = Backup([*paths.values(), SYSCTL])
        start = fresh or repairing or was_active
        attempted = False
        changed_site = False
        try:
            if fresh:
                atomic_file(pending, changed)
            issue_certificate(domain, config["email"], config["cert"],
                              previous["domain"] if previous and site.is_file() else None)
            atomic_file(site, site_config, 0o644)
            changed_site = True
            reload_nginx(domain)
            apply_network_tuning()
            if candidate != binary:
                atomic_file(version, tag + "\n")
                atomic_file(binary, candidate.read_bytes(), 0o755)
            atomic_file(core, wire_config)
            atomic_file(paths["unit"], core_service(target, binary, core, config["cert"]), 0o644)
            system("daemon-reload")
            if start:
                attempted = True
                system("restart", name)
                retry(lambda: healthy(target, config), "节点未通过本机连接检查。")
            if fresh or repairing:
                system("enable", name)
            atomic_file(paths["uri"], share + "\n")
            renewal()
            if pending.exists():
                pending.replace(state)
            else:
                atomic_file(state, changed)
        except Exception:
            if attempted:
                system("stop", name, check=False)
            if (fresh or repairing) and not was_enabled:
                system("disable", name, check=False)
            backup.restore()
            run("sysctl", "--system", check=False, capture=True)
            system("daemon-reload")
            if changed_site:
                reload_nginx()
            if attempted and was_active:
                prior_service(name, was_active, was_enabled)
            raise
    if repairing:
        return "已恢复并启动节点。"
    if previous and previous["cert"] != config["cert"]:
        return (f"节点域名已修改。确认新域名连接成功、其他服务也不再使用旧证书后，"
                f"可在 VPS 上运行 sudo certbot delete --cert-name {previous['cert']}。")
    return "已创建并启动节点。" if fresh else "节点配置已修改。"


def set_enabled(target, start):
    config = node_config(target)
    if not config:
        raise ValueError("请先创建节点。")
    name = unit_name(target)
    was_active, was_enabled = active(name), enabled(name)
    try:
        system("enable" if start else "disable", "--now", name)
        if start:
            retry(lambda: healthy(target, config), "节点未通过本机连接检查。")
    except Exception:
        if not was_active:
            system("stop", name, check=False)
        prior_service(name, was_active, was_enabled)
        raise
    return "节点已启用。" if start else "节点已停用。"


def upgrade(target, tag):
    config = node_config(target)
    if not config:
        raise ValueError("请先创建节点。")
    binary, core, version = core_paths(target)
    installed = read_text(version)
    if installed and version_key(tag) <= version_key(installed):
        raise ValueError(f"核心已安装 {installed}，请选择较新的版本。")
    name = unit_name(target)
    was_active = active(name)
    with tempfile.TemporaryDirectory(prefix="core-", dir=ADMIN) as temp:
        candidate, _ = acquire_core(target, Path(temp), tag)
        check_candidate(target, candidate, core)
        backup = Backup((binary, version))
        try:
            atomic_file(binary, candidate.read_bytes(), 0o755)
            if was_active:
                system("restart", name)
                retry(lambda: healthy(target, config), "新版核心未通过本机连接检查。")
            atomic_file(version, tag + "\n")
        except Exception:
            backup.restore()
            if was_active:
                system("reset-failed", name, check=False)
                system("restart", name)
            raise
    return f"核心已升级至 {tag}。"
