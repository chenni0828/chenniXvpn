#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'HELP'
sudo bash install.sh [--upgrade | --reconfigure | --status]
sudo bash install.sh --from-github [TAG] [--upgrade]
  --mode ssh --ssh-host [user@]主机或SSH别名 [--ssh-port SSH端口]
  --mode https --domain 管理域名 --email 证书邮箱
  --port 管理端口     --non-interactive     --admin-password-stdin
  --dry-run 预览      --quiet 精简日志      --status --json 查询本机
HELP
}

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
remote=false
local_action=false
for arg in "$@"; do
    case "$arg" in
        --help|-h) usage; exit 0 ;;
        --from-github|--from-github=*) remote=true ;;
        --status|--reconfigure) local_action=true ;;
    esac
done

if [[ ! -x /usr/bin/python3 ]]; then
    printf '安装前校验需要 /usr/bin/python3。请先安装 python3，再重新运行。\n' >&2
    exit 1
fi
unset CHENNIXVPN_VERIFIED_ARCHIVE_SHA256
if [[ $remote == false ]]; then
    if [[ ! -f $here/server/deployment.py && $local_action == true ]]; then
        here=/opt/chennixvpn/current
    fi
    if [[ ! -f $here/server/deployment.py ]]; then
        printf '请使用本版完整源码，或用 --from-github [TAG] 安装或升级。\n' >&2
        exit 2
    fi
    exec /usr/bin/python3 -IB "$here/server/deployment.py" "$@"
fi
if [[ $local_action == true ]]; then
    printf '%s\n' '--status 与 --reconfigure 读取本机安装，请单独使用。' >&2
    exit 2
fi
if (( EUID != 0 )); then
    printf '请使用 sudo bash 运行安装程序。\n' >&2
    exit 1
fi
if [[ ! -r /etc/os-release || ! -d /run/systemd/system ]]; then
    printf '服务端需要 systemd Linux。\n' >&2
    exit 1
fi
source /etc/os-release
case "${ID:-}" in
    debian) minimum=12 ;;
    ubuntu) minimum=22.04 ;;
    *) minimum='' ;;
esac
if [[ -z $minimum ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge "$minimum"; then
    printf '服务端支持 Debian 12+ 或 Ubuntu 22.04+。\n' >&2
    exit 1
fi
case $(uname -m) in
    x86_64|aarch64) ;;
    *) printf '服务端支持 amd64 和 arm64。\n' >&2; exit 1 ;;
esac
if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
    printf '验证 GitHub HTTPS 需要 ca-certificates。请安装后重试。\n' >&2
    exit 1
fi

# Both GitHub entry points use the same verifier. FD 0 belongs to the installer.
exec /usr/bin/python3 -IB /dev/fd/3 "$@" 3<<'PY'
import argparse
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

project = "chenni0828/chenniXvpn"
asset_name = "chennixvpn-server.tar.gz"
maximum = 160 * 1024**2
tag_pattern = r"v[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}"
parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
parser.add_argument("--from-github", nargs="?", const="", required=True)
options, forwarded = parser.parse_known_args()
tag = options.from_github
if tag and not re.fullmatch(tag_pattern, tag):
    raise SystemExit("请输入版本标签，例如 v0.1.0。")
try:
    ref = f"tags/{tag}" if tag else "latest"
    request = Request(f"https://api.github.com/repos/{project}/releases/{ref}",
                      headers={"User-Agent": "chennixvpn", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=15) as response:
        release = json.loads(response.read(2 * 1024**2))
    if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
        raise ValueError("GitHub Release 响应格式无效。")
    published = release.get("tag_name")
    if (not isinstance(published, str) or not re.fullmatch(tag_pattern, published)
            or release.get("draft") is not False or release.get("prerelease") is not False
            or (tag and published != tag)):
        raise ValueError("GitHub Release 版本无效。")
    if tuple(map(int, published[1:].split("."))) < (0, 1, 0):
        raise ValueError("请选择 v0.1.0 或更高版本。")
    asset = next((item for item in release["assets"] if isinstance(item, dict) and item.get("name") == asset_name), {})
    expected_digest = asset.get("digest")
    expected_size = asset.get("size")
    if (not isinstance(expected_digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest)
            or type(expected_size) is not int or not 0 < expected_size <= maximum):
        raise ValueError("GitHub 未提供发行包及其 SHA-256 校验值。")
    url = asset.get("browser_download_url")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{project}/releases/download/"):
        raise ValueError("GitHub 发行包地址无效。")
    with tempfile.TemporaryDirectory(prefix="chennixvpn-") as directory:
        stage = Path(directory)
        archive = stage / asset_name
        digest = hashlib.sha256()
        size = 0
        with urlopen(url, timeout=30) as response, archive.open("xb") as output:
            final = urlsplit(response.url)
            if final.scheme != "https" or final.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}:
                raise ValueError("GitHub 下载地址无效。")
            for block in iter(lambda: response.read(1024**2), b""):
                size += len(block)
                if size > expected_size:
                    raise ValueError("发行包超过发布大小。")
                digest.update(block)
                output.write(block)
        if size != expected_size or "sha256:" + digest.hexdigest() != expected_digest:
            raise ValueError("发行包 SHA-256 校验失败。")
        total = 0
        seen = set()
        with tarfile.open(archive, "r:gz") as package:
            for item in package:
                name = PurePosixPath(item.name)
                if (len(seen) >= 1500 or not name.parts or name.parts[0] != "chennixvpn" or
                        ".." in name.parts or name in seen or not (item.isdir() or item.isreg())):
                    raise ValueError("发行包目录无效。")
                seen.add(name)
                target = stage.joinpath(*name.parts)
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    total += item.size
                    if total > maximum:
                        raise ValueError("发行包展开后超过大小限制。")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with package.extractfile(item) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
        source = stage / "chennixvpn"
        if (source / "VERSION").read_text().strip() != published:
            raise ValueError("发行包的版本与 Release 不一致。")
        entry = source / "server/deployment.py"
        if not entry.is_file():
            raise ValueError("发行包缺少部署入口。")
        env = dict(os.environ, CHENNIXVPN_VERIFIED_ARCHIVE_SHA256=digest.hexdigest())
        sys.exit(subprocess.call((sys.executable, "-IB", entry, *forwarded), env=env))
except (ValueError, OSError, http.client.HTTPException, tarfile.TarError) as exc:
    raise SystemExit(f"GitHub 安装失败：{exc}。请确认指定 Release 已发布服务端包。") from None
PY
