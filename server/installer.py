"""CLI for planning, applying and inspecting a panel deployment."""

import argparse
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import deployment as d
import panel_access as access
from passwords import read_admin_hash
from releases import ARCHIVE_COMMIT, version_key


def arguments(argv):
    parser = argparse.ArgumentParser(prog="install.sh", description="安装、升级或重新配置 chenniXvpn 面板",
                                     allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    for name in ("upgrade", "reconfigure", "status"):
        group.add_argument("--" + name, action="store_true")
    parser.add_argument("--mode", choices=("ssh", "https"))
    parser.add_argument("--ssh-host", metavar="[USER@]HOST")
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--port", type=int)
    for name in ("admin-password-stdin", "non-interactive", "dry-run", "quiet", "json"):
        parser.add_argument("--" + name, action="store_true")
    args, extra = parser.parse_known_args(argv)
    if extra:
        parser.error("存在未知参数，请查看 --help。")
    access_given = any(getattr(args, key) is not None for key in ("mode", "ssh_host", "ssh_port", "domain", "email", "port"))
    if args.status and (access_given or args.admin_password_stdin or args.dry_run):
        parser.error("--status 是只读查询，不能同时指定部署配置。")
    if args.json and not args.status:
        parser.error("--json 配合 --status 使用。")
    if args.upgrade and access_given:
        parser.error("--upgrade 保留访问设置；修改入口请使用 --reconfigure。")
    if args.admin_password_stdin and (args.upgrade or args.reconfigure or not args.non_interactive):
        parser.error("--admin-password-stdin 仅用于 --non-interactive 首装。")
    return args, access_given


def unknown_source():
    return dict(kind="unknown", tag=None, commit=None, dirty=None, sha256=None)


def source_info(source, tag, digest):
    info = unknown_source()
    info["kind"] = "source"
    if re.fullmatch(r"[0-9a-f]{40}", ARCHIVE_COMMIT):
        info["commit"] = ARCHIVE_COMMIT
    if digest:
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("发行包摘要格式无效。")
        info.update(kind="github-release", tag=tag, sha256=digest)
    elif (source / ".git").exists() and shutil.which("git"):
        git = ("git", "--no-optional-locks", "-c", f"safe.directory={source.as_posix()}", "-c",
               "core.fsmonitor=false", "-C", source)
        head = d.run(*git, "rev-parse", "--verify", "HEAD", check=False, capture=True)
        if not head.returncode and re.fullmatch(r"[0-9a-f]{40,64}", head.stdout.strip()):
            changes = d.run(*git, "status", "--porcelain", "--untracked-files=all", "--",
                            "install.sh", "VERSION", "server", "frontend", "client", capture=True)
            info.update(kind="git", commit=head.stdout.strip(), dirty=bool(changes.stdout))
    return info


def installed_state():
    version = d.read_text(d.CURRENT / "VERSION") or None
    config = d.settings()
    if version:
        version_key(version)
    if config is not None:
        if not isinstance(config, dict) or config.get("mode") not in ("ssh", "https"):
            raise ValueError("本机 panel.json 的访问方式无效。")
        for key in ("port", "local_port"):
            d.port_value(config.get(key))
        if config["mode"] == "https":
            domain = d.domain_value(config.get("domain"))
            d.email_value(config.get("email"))
            if config.get("cert") != d.node_cert_name("panel", domain):
                raise ValueError("本机面板证书名称无效。")
        else:
            host = config.get("ssh_host")
            user = config.get("ssh_user")
            if not isinstance(host, str) or not host or "@" in host or (user is not None and not isinstance(user, str)):
                raise ValueError("本机 panel.json 的 SSH 目标无效。")
            access.parse_ssh_target(access.ssh_target(config))
            if config.get("ssh_port") is not None:
                d.port_value(config["ssh_port"])
    return version, config


def owned_files_exist():
    paths = (d.CURRENT, d.ETC / "admin.hash", d.ETC / "panel.json", d.NGINX / "chennixvpn-panel.conf",
             d.UNITS / d.PANEL, d.UNITS / d.TRAFFIC)
    return any(path.exists() or path.is_symlink() for path in paths)


def installed_source():
    raw = d.read_text(d.CURRENT / "source.json")
    info = unknown_source()
    if raw:
        saved = json.loads(raw)
        if not isinstance(saved, dict):
            raise ValueError("本机 source.json 的格式无效。")
        info.update({key: saved[key] for key in info if key in saved})
    return info


def swap_bytes():
    for line in d.read_text(Path("/proc/meminfo")).splitlines():
        match = re.fullmatch(r"SwapTotal:\s+(\d+)\s+kB", line)
        if match:
            return int(match[1]) * 1024
    return None


def status():
    version, config = installed_state()
    installed = bool(version and config)
    services = {name: dict(active=d.active(unit), enabled=d.enabled(unit))
                for name, unit in (("panel", d.PANEL), ("traffic", d.TRAFFIC))}
    local_auth = None
    if installed:
        try:
            local_auth = d.check_panel(config)
        except (OSError, http.client.HTTPException):
            local_auth = False
        healthy = local_auth and all(service["active"] and service["enabled"] for service in services.values())
        state = "healthy" if healthy else "degraded"
    else:
        state = "incomplete" if owned_files_exist() else "not_installed"
    return dict(state=state, installed=installed, version=version, mode=config["mode"] if config else None,
                entry=d.panel_origin(config) if config else None,
                ssh_command=access.ssh_command(config) if config else None, services=services,
                local_auth=local_auth, public_access="not_checked", source=installed_source(), swap_bytes=swap_bytes())


def print_origin(entry, command):
    print(f"面板入口 {entry}，账号 admin。")
    if command:
        print(command)


def print_source(info):
    dirty = "（工作树有改动）" if info["dirty"] else ""
    print(f"来源 {info['kind']}，commit {info['commit'] or '未知'}{dirty}，"
          f"Release {info['tag'] or '无记录'}，已验证包 SHA-256 {info['sha256'] or '无记录'}。")


def print_status(report, as_json=False):
    if as_json:
        print(json.dumps(report, ensure_ascii=False))
        return
    print(f"部署状态 {report['state']}，版本 {report['version'] or '未知'}。")
    if report["entry"]:
        print_origin(report["entry"], report["ssh_command"])
    print_source(report["source"])
    for name, service in report["services"].items():
        print(f"{name}: active={service['active']} enabled={service['enabled']}")
    print(f"本机认证检查 {report['local_auth']}；公网连通性未从外部验证。")


def execute(source, args, access_given):
    with d.deployment_lock(read_only=True):
        if args.status:
            print_status(status(), args.json)
            return
        previous_version, previous = installed_state()
        if (not previous and owned_files_exist()) or (previous and not previous_version):
            raise RuntimeError("检测到不完整的部署，请先检查配置和服务。")

    tag = d.read_text(source / "VERSION")
    version_key(tag)
    if not previous and (args.upgrade or args.reconfigure):
        raise ValueError("此主机尚未安装，请先完成首次安装。")
    if previous_version and version_key(tag) < version_key(previous_version):
        raise ValueError(f"当前已安装 {previous_version}，请使用相同或更高版本。")
    if args.reconfigure and tag != previous_version:
        raise ValueError(f"请先用本版 --upgrade 从 {previous_version} 升级，再切换访问方式。")

    tty = sys.stdin.isatty() and not args.non_interactive
    if not previous or args.reconfigure:
        config = access.requested_settings(args, previous, prompt=tty)
    else:
        config = previous
        if access_given:
            if args.mode is None:
                args.mode = previous["mode"]
            if access.requested_settings(args, previous, prompt=False) != previous:
                raise ValueError("已有部署的访问配置不同，请使用 --reconfigure。")
    if previous_version == tag and config == previous:
        print("已安装相同版本且访问配置相同。")
        with d.deployment_lock(read_only=True):
            print_status(status())
        return
    if not previous and not args.dry_run and not tty and not (args.non_interactive and args.admin_password_stdin):
        raise ValueError("无人值守首装需要 --non-interactive 和 --admin-password-stdin。")
    if not (args.dry_run or tty or args.non_interactive or args.upgrade):
        raise ValueError("无交互终端。请预览并确认后使用 --non-interactive。")

    action = "切换面板访问方式" if args.reconfigure else "升级" if previous else "首次安装"
    info = installed_source() if args.reconfigure else source_info(
        source, tag, os.environ.get("CHENNIXVPN_VERIFIED_ARCHIVE_SHA256"))
    addresses = access.preflight(config, previous) if not previous or args.reconfigure else []
    print(f"{action} chenniXvpn {tag}，主机 {socket.gethostname()}，模式 {config['mode']}。")
    print_origin(d.panel_origin(config), access.ssh_command(config))
    print_source(info)
    if addresses:
        print(f"本机 DNS 解析 {', '.join(addresses)}。证书邮箱 {config['email']}，"
              f"主机防火墙和云安全组需放行 TCP 80 与 TCP {config['port']}。")
    if args.reconfigure:
        print(f"原入口 {d.panel_origin(previous)}。将更新面板服务和相关入口，保留密码、数据库及节点。")
    elif previous:
        print("将备份数据库、替换应用版本并恢复原服务运行状态。")
    else:
        print("将安装缺失依赖、创建服务用户、写入面板配置并启用面板和流量采集服务。")
    sys.stdout.flush()
    if args.dry_run:
        print("预览完成。")
        return
    if tty and not args.upgrade and input("确认执行？[y/N] ").strip().lower() not in ("y", "yes"):
        raise ValueError("已取消。")
    admin_hash = read_admin_hash(args.admin_password_stdin) if not previous else None

    os.umask(0o022)
    with d.deployment_lock():
        if installed_state() != (previous_version, previous) or (not previous and owned_files_exist()):
            raise RuntimeError("预览后部署状态已变化，请重新运行。")
        if not previous or args.reconfigure:
            access.preflight(config, previous)
        if args.reconfigure:
            access.reconfigure(previous, config)
        else:
            d.install_project_locked(source, config, admin_hash=admin_hash, provenance=info)
        print_status(status())


def main(argv=None):
    args, access_given = arguments(argv)
    try:
        d.validate_platform()
        d.QUIET = args.quiet
        execute(d.SERVER.parent, args, access_given)
    except (ValueError, RuntimeError, OSError, EOFError, subprocess.TimeoutExpired) as exc:
        if args.status and args.json:
            print(json.dumps(dict(state="error", error=str(exc)), ensure_ascii=False))
        else:
            print(f"部署失败：{exc}", file=sys.stderr)
        return 1
    return 0
