"""Build panel access settings and switch the live ingress under the deployment lock."""

import http.client
import ipaddress
import json
import re
import shutil
import socket
import ssl
import sys
import tempfile
from pathlib import Path

import deployment as d


def ssh_target(config):
    host = config.get("ssh_host")
    user = config.get("ssh_user")
    return f"{user}@{host}" if host and user else host


def ssh_command(config):
    target = ssh_target(config)
    if config["mode"] != "ssh" or not target:
        return None
    port = config["port"]
    ssh_port = f" -p {config['ssh_port']}" if config.get("ssh_port") else ""
    return f"ssh -N -o ExitOnForwardFailure=yes{ssh_port} -L 127.0.0.1:{port}:127.0.0.1:{port} {target}"


def parse_ssh_target(target):
    user, sep, host = target.rpartition("@")
    if sep and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", user):
        raise ValueError("--ssh-host 中的 SSH 用户名无效。")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        if "%" in host:
            raise ValueError
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", host):
            raise ValueError("--ssh-host 需要实际 SSH 目标，例如 admin@vps 或本机 SSH 别名。") from None
    return user or None, host


def vless_ports():
    return {node["port"] for pending in (False, True) if (node := d.node_config("vless", pending))}


def ssh_listener_unchanged(config, previous):
    return (previous and previous["mode"] == config["mode"] == "ssh"
            and previous["local_port"] == config["local_port"])


def requested_settings(args, previous, *, prompt):
    def value(option, label, default=None):
        supplied = getattr(args, option)
        if supplied is not None:
            return supplied
        if prompt:
            suffix = f" [{default}]" if default is not None else ""
            entry = input(f"{label}{suffix}：").strip()
            if entry:
                return entry
        if default is None:
            raise ValueError(f"需要明确指定 --{option.replace('_', '-')}（{label}）。")
        return default

    mode = value("mode", "访问方式，输入 ssh 或 https")
    if mode not in ("ssh", "https"):
        raise ValueError("访问方式须为 ssh 或 https。")
    previous = previous or {}
    prior = previous if previous.get("mode") == mode else {}
    port = d.port_value(int(value("port", "面板管理端口", prior.get("port", 9080 if mode == "ssh" else 443))))
    if port == d.VLESS_LOOPBACK or (port < 1024 and not (mode == "https" and port == 443)):
        raise ValueError("管理端口须为 1024–65535，HTTPS 也可用 443；18080 预留给 VLESS。")
    if mode == "ssh":
        if args.domain is not None or args.email is not None:
            raise ValueError("SSH 模式不能使用 --domain 或 --email。")
        user, host = parse_ssh_target(value("ssh_host", "平时登录 VPS 的 SSH 目标", ssh_target(prior) or None))
        config = dict(mode=mode, domain=None, email=None, port=port, local_port=port, ssh_user=user, ssh_host=host)
        ssh_port = args.ssh_port
        if ssh_port is None and (user, host) == (prior.get("ssh_user"), prior.get("ssh_host")):
            ssh_port = prior.get("ssh_port")
        if ssh_port is not None:
            config["ssh_port"] = d.port_value(ssh_port)
        return config

    if args.ssh_host is not None or args.ssh_port is not None:
        raise ValueError("HTTPS 模式不能使用 --ssh-host 或 --ssh-port。")
    domain = d.domain_value(value("domain", "管理域名", prior.get("domain")))
    email = d.email_value(value("email", "证书邮箱", prior.get("email")))
    local = previous.get("local_port")
    reserved = {port} | vless_ports()
    if not local or local in reserved:
        local = next((i for i in range(9080, 9100) if i not in reserved and d.loopback_available(i)), None)
    if local is None:
        raise ValueError("没有可用的面板回环端口（9080–9099）。")
    return dict(mode=mode, domain=domain, email=email, port=port, local_port=local,
                cert=d.node_cert_name("panel", domain))


def preflight(config, previous):
    if ssh_listener_unchanged(config, previous):
        return []
    local = config["local_port"]
    releases_public_port = (previous and previous["mode"] == "https" and config["mode"] == "ssh"
                            and previous["port"] == local and (d.NGINX / "chennixvpn-panel.conf").is_file())
    if not previous or previous["local_port"] != local or not d.active(d.PANEL):
        if not releases_public_port and not d.loopback_available(local):
            raise ValueError(f"本机 TCP {local} 已被占用。")
    if local in vless_ports():
        raise ValueError("面板回环端口与现有 VLESS 公网端口冲突。")
    if config["mode"] == "https":
        domain = config["domain"]
        d.validate_new_domain(domain, "panel")
        try:
            addresses = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError(f"本机 DNS 无法解析管理域名 {domain}。") from None
        d.check_ingress(config, previous)
        return sorted({address[4][0] for address in addresses})
    return []


def retired(config):
    try:
        _, challenge = d.panel_response(config, verify_tls=False)
        # An unmatched Host can reach another site on the shared HTTPS port.
        return not challenge.startswith(d.PANEL_REALM)
    except (ConnectionRefusedError, http.client.RemoteDisconnected):
        return True
    except ssl.SSLError as exc:
        # Some default vhosts explicitly reject unknown SNI names.
        if exc.reason in {"TLSV1_UNRECOGNIZED_NAME", "TLSV1_ALERT_UNRECOGNIZED_NAME", "WRONG_VERSION_NUMBER"}:
            return True
        raise


def reconfigure(previous, config):
    panel_path = d.ETC / "panel.json"
    if ssh_listener_unchanged(config, previous):
        # Updating the SSH client destination doesn't change any listener.
        d.atomic_file(panel_path, json.dumps(config))
        return
    unit = d.UNITS / d.PANEL
    site = d.NGINX / "chennixvpn-panel.conf"
    https = config["mode"] == "https"
    old_https = previous["mode"] == "https"
    paths = [panel_path, unit]
    services = [d.PANEL]
    if https or old_https:
        paths.append(site)
        services.append("nginx.service")
    if https:
        paths.append(d.renewal_hook())
        services.append("certbot.timer")
    backup = d.Backup(paths)
    states = {name: (d.active(name), d.enabled(name)) for name in services}
    recovery = Path(tempfile.mkdtemp(prefix="access-rollback-", dir=d.ADMIN))
    backup.persist(recovery, states)
    panel_changed = False
    try:
        if https:
            print("正在检查 Nginx 和面板证书。", file=sys.stderr, flush=True)
            d.packages("nginx", "certbot", "iproute2")
            d.check_ingress(config, previous)
            d.issue_certificate(config["domain"], config["email"], config["cert"],
                                previous.get("domain") if old_https and site.is_file() else None)
        elif old_https:
            site.unlink(missing_ok=True)
            if states["nginx.service"][0]:
                d.reload_nginx(start_if_inactive=False)
            if config["local_port"] == previous["port"]:
                d.retry(lambda: d.loopback_available(config["local_port"]),
                        "原公网端口仍有其他站点监听，请选择其他 SSH 面板端口。", attempts=5)

        print("正在切换面板入口并验证本机认证。", file=sys.stderr, flush=True)
        d.atomic_file(unit, d.panel_service(config), 0o644)
        panel_changed = True
        d.system("daemon-reload")
        d.system("restart", d.PANEL)
        if https:
            d.atomic_file(site, d.panel_site(config), 0o644)
            d.reload_nginx(config["domain"])
            d.renewal()
        d.retry(lambda: d.check_panel(config), "新入口未通过本机认证检查。")
        if old_https and d.panel_origin(previous) != d.panel_origin(config):
            d.retry(lambda: retired(previous), "旧 HTTPS 入口仍可访问面板或无法确认已撤除。")
        if not states[d.PANEL][0]:
            d.system("stop", d.PANEL)
        d.atomic_file(panel_path, json.dumps(config))
    except (Exception, KeyboardInterrupt) as original:
        try:
            if panel_changed:
                d.system("stop", d.PANEL)
            backup.restore()
            d.system("daemon-reload")
            d.restore_panel_services({name: state for name, state in states.items() if name != d.PANEL})
            if (https or old_https) and states["nginx.service"][0]:
                d.reload_nginx(start_if_inactive=False)
            if panel_changed and https and previous["local_port"] == config["port"]:
                d.retry(lambda: d.loopback_available(previous["local_port"]),
                        "原面板回环端口尚未释放。", attempts=5)
            d.restore_panel_services({d.PANEL: states[d.PANEL]})
            if states[d.PANEL][0]:
                d.retry(lambda: d.check_panel(previous), "旧面板入口恢复检查失败。")
        except Exception as restore_error:
            raise RuntimeError(f"切换失败且回滚未完成。恢复目录 {recovery}。"
                               f"切换错误：{original}；回滚错误：{restore_error}") from restore_error
        shutil.rmtree(recovery)
        raise
    shutil.rmtree(recovery)
