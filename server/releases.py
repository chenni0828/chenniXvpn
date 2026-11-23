"""Load stable GitHub releases and verify the assets before executing them."""

import hashlib
import json
import platform
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


REPOSITORIES = {
    "project": "chenni0828/chenniXvpn",
    "hy2": "HyNetworks/hysteria",
    "vless": "XTLS/Xray-core",
}
SERVER_ASSET = "chennixvpn-server.tar.gz"
SIZE_LIMIT = 160 * 1024**2
# git archive expands this marker for source packages built from a commit.
ARCHIVE_COMMIT = "$Format:%H$"


def version_key(tag):
    match = re.fullmatch(r"(?:app/)?v(\d{1,5})\.(\d{1,5})\.(\d{1,5})(?:\.(\d{1,5}))?", tag)
    if not match:
        raise ValueError("需要正式版标签，例如 v0.2.0 或 app/v2.6.0。")
    return tuple(int(part or 0) for part in match.groups())


def release(target, tag=None):
    if tag is not None:
        version_key(tag)
    reference = "latest" if tag is None else "tags/" + quote(tag, safe="")
    request = Request(f"https://api.github.com/repos/{REPOSITORIES[target]}/releases/{reference}",
                      headers={"Accept": "application/vnd.github+json", "User-Agent": "chennixvpn"})
    try:
        with urlopen(request, timeout=15) as response:
            data = json.loads(response.read(2 * 1024**2 + 1))
    except HTTPError as exc:
        if exc.code == 404 and target == "project":
            raise RuntimeError("找不到对应的公开正式 Release，请确认标签或使用固定提交的源码。") from None
        raise RuntimeError(f"GitHub Release 请求失败（HTTP {exc.code}）。") from None
    except (URLError, TimeoutError):
        raise RuntimeError("无法连接 GitHub，请检查 VPS 网络后重试。") from None
    current = data.get("tag_name", "")
    version_key(current)
    if data.get("draft") or data.get("prerelease") or (tag is not None and current != tag):
        raise ValueError("指定的 GitHub Release 不是对应的正式版本。")
    return data


def download_asset(data, asset_name, output):
    asset = next((asset for asset in data.get("assets", []) if asset.get("name") == asset_name), None)
    if not asset:
        raise RuntimeError(f"GitHub Release 中没有 {asset_name}。")
    url = asset.get("browser_download_url", "")
    digest = asset.get("digest") or ""
    expected_size = asset.get("size")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or
            "/releases/download/" not in parsed.path or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or
            type(expected_size) is not int or not 0 < expected_size <= SIZE_LIMIT):
        raise RuntimeError(f"GitHub 未提供 {asset_name} 的有效 SHA-256 或文件大小。")
    result = hashlib.sha256()
    total = 0
    try:
        with urlopen(Request(url, headers={"User-Agent": "chennixvpn"}), timeout=30) as response, output.open("xb") as file:
            final = urlsplit(response.url)
            if final.scheme != "https" or final.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}:
                raise RuntimeError("GitHub 下载地址无效。")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                total += len(chunk)
                if total > expected_size:
                    raise RuntimeError("下载文件大小与 Release 不符。")
                result.update(chunk)
                file.write(chunk)
    except (URLError, TimeoutError):
        raise RuntimeError(f"下载 {asset_name} 失败。") from None
    checksum = result.hexdigest()
    if total != expected_size or f"sha256:{checksum}" != digest:
        raise RuntimeError(f"SHA-256 校验失败：{asset_name}。")
    return checksum


def core_asset(target):
    architecture = platform.machine()
    arguments = {"x86_64": ("amd64", "64"), "aarch64": ("arm64", "arm64-v8a")}
    if architecture not in arguments:
        raise RuntimeError("服务端支持 amd64 和 arm64。")
    cpu, xray = arguments[architecture]
    return f"hysteria-linux-{cpu}" if target == "hy2" else f"Xray-linux-{xray}.zip"


def unpack_project(archive, destination, tag):
    total = 0
    seen = set()
    with tarfile.open(archive, "r:gz") as package:
        for member in package:
            path = PurePosixPath(member.name)
            if len(seen) >= 1500 or not path.parts or path.parts[0] != "chennixvpn" or ".." in path.parts:
                raise RuntimeError("项目发行包目录无效。")
            if path in seen or not (member.isdir() or member.isreg()):
                raise RuntimeError("项目发行包含有重复文件或链接。")
            seen.add(path)
            output = destination.joinpath(*path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > SIZE_LIMIT:
                raise RuntimeError("项目发行包展开后超过大小限制。")
            output.parent.mkdir(parents=True, exist_ok=True)
            with package.extractfile(member) as source, output.open("xb") as file:
                shutil.copyfileobj(source, file)
    root = destination / "chennixvpn"
    if not (root / "install.sh").is_file() or (root / "VERSION").read_text().strip() != tag:
        raise RuntimeError("项目发行包的版本与 Release 不一致。")
    return root
