"""Build panel access settings and switch the live ingress under the deployment lock."""

import http.client
import json
import shutil
import socket
import ssl
import sys

import deployment as d


def vless_ports():
    return {node["port"] for pending in (False, True) if (node := d.node_config("vless", pending))}


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

    prior = previous or {}
    port = d.port_value(int(value("port", "面板 HTTPS 端口", prior.get("port", 443))))
    if port == d.VLESS_LOOPBACK or (port < 1024 and port != 443):
        raise ValueError("管理端口须为 1024–65535，HTTPS 也可用 443；18080 预留给 VLESS。")
    domain = d.domain_value(value("domain", "管理域名", prior.get("domain")))
    email = d.email_value(value("email", "证书邮箱", prior.get("email")))
    local = prior.get("local_port")
    reserved = {port} | vless_ports()
    if not local or local in reserved:
        local = next((i for i in range(9080, 9100) if i not in reserved and d.loopback_available(i)), None)
    if local is None:
        raise ValueError("没有可用的面板回环端口（9080–9099）。")
    return dict(domain=domain, email=email, port=port, local_port=local,
                cert=d.node_cert_name("panel", domain))


def preflight(config, previous):
    local = config["local_port"]
    if not previous or previous["local_port"] != local or not d.active(d.PANEL):
        if not d.loopback_available(local):
            raise ValueError(f"本机 TCP {local} 已被占用。")
    if local in vless_ports():
        raise ValueError("面板回环端口与现有 VLESS 公网端口冲突。")
    domain = config["domain"]
    d.validate_new_domain(domain, "panel")
    try:
        addresses = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"本机 DNS 无法解析管理域名 {domain}。") from None
    d.check_ingress(config, previous)
    return sorted({address[4][0] for address in addresses})


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
    unit = d.UNITS / d.PANEL
    site = d.NGINX / "chennixvpn-panel.conf"
    paths = [panel_path, unit, site, d.renewal_hook()]
    services = [d.PANEL, "nginx.service", "certbot.timer"]
    backup = d.Backup(paths)
    states = {name: (d.active(name), d.enabled(name)) for name in services}
    panel_changed = False
    try:
        print("正在检查 Nginx 和面板证书。", file=sys.stderr, flush=True)
        had_ss = bool(shutil.which("ss", path=d.ENV["PATH"]))
        d.packages("nginx", "certbot", "iproute2")
        if not had_ss:
            d.check_ingress(config, previous)
        d.issue_certificate(config["domain"], config["email"], config["cert"],
                            previous.get("domain") if site.is_file() else None)

        print("正在切换面板 HTTPS 入口并验证本机认证。", file=sys.stderr, flush=True)
        d.atomic_file(unit, d.panel_service(config), 0o644)
        panel_changed = True
        d.system("daemon-reload")
        d.system("restart", d.PANEL)
        d.atomic_file(site, d.panel_site(config), 0o644)
        d.reload_nginx(config["domain"])
        d.renewal()
        d.retry(lambda: d.check_panel(config), "新入口未通过本机认证检查。")
        if d.panel_origin(previous) != d.panel_origin(config):
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
            if states["nginx.service"][0]:
                d.reload_nginx(start_if_inactive=False)
            if panel_changed and previous["local_port"] == config["port"]:
                d.retry(lambda: d.loopback_available(previous["local_port"]),
                        "原面板回环端口尚未释放。", attempts=5)
            d.restore_panel_services({d.PANEL: states[d.PANEL]})
            if states[d.PANEL][0]:
                d.retry(lambda: d.check_panel(previous), "旧面板入口恢复检查失败。")
        except Exception as restore_error:
            raise RuntimeError(f"切换失败且回滚未完成。切换错误：{original}；回滚错误：{restore_error}") from restore_error
        raise
