"""The panel's root-owned, allowlisted operations and persistent job status."""

import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment as deploy
import nodes
from releases import SERVER_ASSET, download_asset, release, unpack_project, version_key


JOBS = deploy.ADMIN / "jobs"
SERVICE = "chennixvpn-operation.service"
TARGETS = ("project", "hy2", "vless")
RUNNING = {"queued", "running"}
OPERATIONS = {"create", "configure", "repair", "enable", "disable", "upgrade", "retire_certificate"}
OPERATIONS.add("delete_release")
OPTIONAL = {"cloudflare", "up_mbps", "down_mbps"}
RELEASE_ID = re.compile(r"(?:app/)?v\d{1,5}\.\d{1,5}\.\d{1,5}(?:\.\d{1,5})?-[0-9a-f]{8}")


class RequestError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def job_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise RequestError("无效的任务 ID。")
    return JOBS / f"{job_id}.json"


def job_read(job_id):
    path = job_path(job_id)
    try:
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        raise RequestError("任务不存在。", 404) from None


def job_write(job):
    deploy.atomic_file(job_path(job["id"]), json.dumps(job, ensure_ascii=False))


def status_view(job):
    if job["state"] in RUNNING and time.time() - job["created_at"] > 4:
        current = deploy.read_text(deploy.RUN / "current-job")
        if current != job["id"] or not deploy.active(SERVICE):
            job = dict(job, state="failed", message="任务已中断，请查看面板状态或系统服务日志后重试。")
    return {key: job[key] for key in ("id", "operation", "target", "state", "message", "created_at")}


def list_jobs():
    jobs = sorted(JOBS.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:20]
    return {"jobs": [status_view(job_read(path.stem)) for path in jobs]}


def request_arguments(request):
    operation, target = request.get("operation"), request.get("target")
    if not isinstance(operation, str) or operation not in OPERATIONS or target not in TARGETS:
        raise RequestError("无效的操作。")
    fields = {key: value for key, value in request.items() if key not in {"action", "operation", "target"}}
    if operation == "retire_certificate":
        if target != "project" or set(fields) != {"cert"} or not isinstance(fields["cert"], str):
            raise RequestError("证书清理参数无效。")
    elif operation == "delete_release":
        if target != "project" or set(fields) != {"release_id"} or not isinstance(fields["release_id"], str):
            raise RequestError("旧版本清理参数无效。")
        if not RELEASE_ID.fullmatch(fields["release_id"]):
            raise RequestError("旧版本标识无效。")
    elif operation in {"create", "configure"} and target != "project":
        if fields.keys() - OPTIONAL != {"domain", "port", "email"}:
            raise RequestError("节点操作需要域名、端口和邮箱。")
        fields = nodes.validate_options(target, fields)
    elif operation == "upgrade":
        if set(fields) != {"version"} or not isinstance(fields["version"], str):
            raise RequestError("请选择要升级的正式版本。")
        version_key(fields["version"])
    elif fields or target == "project":
        raise RequestError("目标或操作参数无效。")
    return operation, target, fields


def enqueue(request):
    import fcntl

    operation, target, fields = request_arguments(request)
    deploy.RUN.mkdir(mode=0o755, exist_ok=True)
    JOBS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (deploy.RUN / "queue.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if deploy.active(SERVICE):
            raise RequestError("服务器正在执行另一个操作，请稍后重试。", 409)
        job_id = secrets.token_hex(16)
        job = dict(id=job_id, operation=operation, target=target, fields=fields, state="queued",
                   message="等待执行。", created_at=int(time.time()))
        job_write(job)
        deploy.atomic_file(deploy.RUN / "current-job", job_id)
        try:
            deploy.run("/usr/bin/systemd-run", f"--unit={SERVICE}", "--collect", "--quiet",
                       "--property=Type=exec", "--property=RuntimeMaxSec=22min",
                       "/usr/bin/python3", "-I", f"{deploy.CURRENT}/server/operations.py", "--run", job_id,
                       capture=True, timeout=8)
        except (RuntimeError, subprocess.TimeoutExpired):
            if not deploy.active(SERVICE):
                job_write(dict(job, state="failed", message="后台操作服务未能启动。"))
                raise RequestError("后台操作服务未能启动。", 503) from None
    return {"id": job_id}


def install_latest(tag):
    installed = deploy.read_text(deploy.CURRENT / "VERSION")
    if installed and version_key(tag) <= version_key(installed):
        raise ValueError(f"项目已安装 {installed}，请选择较新的版本。")
    published = release("project", tag)
    with tempfile.TemporaryDirectory(prefix="upgrade-", dir=deploy.ADMIN) as temp:
        path = Path(temp)
        archive = path / SERVER_ASSET
        digest = download_asset(published, SERVER_ASSET, archive)
        deploy.run_package(unpack_project(archive, path, tag), upgrade=True, release_sha256=digest)
    return f"面板已升级至 {tag}。"


def current_release_id():
    try:
        target = os.readlink(deploy.CURRENT)
        current = (deploy.CURRENT.parent / target).resolve(strict=True)
        releases = (deploy.BASE / "releases").resolve(strict=True)
    except (OSError, RuntimeError):
        raise RuntimeError("无法确认当前面板版本，已停止清理。") from None
    if current.parent != releases or not current.is_dir() or not RELEASE_ID.fullmatch(current.name):
        raise RuntimeError("当前面板目录不符合版本管理要求，已停止清理。")
    return current.name


def release_source(path):
    source = {"kind": "unknown", "tag": None, "commit": None}
    try:
        metadata = path / "source.json"
        if metadata.is_symlink():
            return source
        saved = json.loads(metadata.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeError, json.JSONDecodeError, OSError):
        return source
    if not isinstance(saved, dict) or saved.get("kind") not in {"source", "github-release", "git", "unknown"}:
        return source
    source["kind"] = saved["kind"]
    if isinstance(saved.get("tag"), str):
        try:
            version_key(saved["tag"])
        except ValueError:
            pass
        else:
            source["tag"] = saved["tag"]
    if isinstance(saved.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40,64}", saved["commit"]):
        source["commit"] = saved["commit"]
    return source


def directory_size(path):
    total = 0
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise ValueError("版本目录包含链接，已停止读取大小。")
            if entry.is_dir(follow_symlinks=False):
                total += directory_size(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
            else:
                raise ValueError("版本目录包含特殊文件，已停止读取大小。")
    return total


def installed_versions_unlocked():
    releases = []
    current = current_release_id()
    try:
        entries = list(os.scandir(deploy.BASE / "releases"))
    except FileNotFoundError:
        entries = []
    for entry in entries:
        if not RELEASE_ID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            continue
        path = Path(entry.path)
        directory_mtime_ns = entry.stat(follow_symlinks=False).st_mtime_ns
        item = {"id": entry.name, "version": entry.name.rsplit("-", 1)[0], "source": release_source(path),
                "size_bytes": None, "deployed_at": int(directory_mtime_ns / 1_000_000_000),
                "directory_mtime_ns": directory_mtime_ns,
                "status": "current" if entry.name == current else "older", "reason": None}
        try:
            if version_key(deploy.read_text(path / "VERSION")) != version_key(item["version"]):
                raise ValueError("目录与 VERSION 不一致，不能删除。")
            item["size_bytes"] = directory_size(path)
        except (ValueError, OSError) as exc:
            item["status"] = "protected"
            item["reason"] = str(exc)
        if item["status"] == "current":
            item["reason"] = "当前运行的版本不能删除。"
        releases.append(item)
    releases.sort(key=lambda item: (version_key(item["version"]), item["deployed_at"], item["id"]), reverse=True)
    rollback = next((item for item in releases if item["status"] == "older"), None)
    if rollback:
        rollback.update(status="rollback", reason="保留为最近一次回滚版本。")
    for item in releases:
        if item["status"] == "older":
            item.update(status="deletable", reason=None)
    return {"releases": releases}


def installed_versions():
    with deploy.deployment_lock(read_only=True):
        return installed_versions_unlocked()


def remove_release(path):
    if not hasattr(os, "O_DIRECTORY"):
        raise OSError("版本目录安全删除需要 Linux 目录描述符支持。")

    def remove(directory_fd):
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise ValueError("版本目录包含链接，已停止清理。")
                if entry.is_dir(follow_symlinks=False):
                    child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        remove(child_fd)
                    finally:
                        os.close(child_fd)
                    os.rmdir(entry.name, dir_fd=directory_fd)
                elif entry.is_file(follow_symlinks=False):
                    os.unlink(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                else:
                    raise ValueError("版本目录包含特殊文件，已停止清理。")

    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        remove(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(path)


def path_changed(release_id, item):
    path = deploy.BASE / "releases" / release_id
    if path.is_symlink() or not path.is_dir():
        return True
    try:
        return (deploy.read_text(path / "VERSION") != item["version"] or directory_size(path) != item["size_bytes"] or
                path.stat().st_mtime_ns != item["directory_mtime_ns"])
    except OSError:
        return True


def delete_release(release_id):
    if not RELEASE_ID.fullmatch(release_id):
        raise ValueError("旧版本标识无效。")
    current = current_release_id()
    if release_id == current:
        raise ValueError("当前运行的版本不能删除。")
    releases = installed_versions_unlocked()["releases"]
    item = next((item for item in releases if item["id"] == release_id), None)
    if not item:
        raise ValueError("旧版本不存在或目录无效。")
    if item["status"] != "deletable":
        raise ValueError(item["reason"] or "该版本受保护，不能删除。")
    if current_release_id() != current:
        raise ValueError("当前版本已变化，请刷新后重试。")
    path = deploy.BASE / "releases" / release_id
    if path_changed(release_id, item):
        raise ValueError("旧版本目录已变化，请刷新后重试。")
    try:
        remove_release(path)
    except OSError:
        raise ValueError("旧版本目录无法安全删除，请刷新后重试。") from None
    return f"已删除旧版本 {item['version']}。"


def execute(job):
    target, operation, fields = (job[key] for key in ("target", "operation", "fields"))
    if operation == "retire_certificate":
        return nodes.retire_certificate(fields["cert"])
    if operation == "delete_release":
        return delete_release(fields["release_id"])
    if target == "project":
        return install_latest(fields["version"])
    if operation in {"create", "configure", "repair"}:
        return nodes.configure(operation, target, fields)
    if operation == "upgrade":
        return nodes.upgrade(target, fields["version"])
    return nodes.set_enabled(target, operation == "enable")


def work(job_id):
    def interrupt(_signum, _frame):
        raise RuntimeError("后台任务超时或被系统中止。")

    signal.signal(signal.SIGTERM, interrupt)
    job = job_read(job_id)
    job_write(dict(job, state="running", message="正在执行。"))
    try:
        job = job_read(job_id)
        if job["state"] != "running":
            raise RuntimeError("操作已中断，请重试。")
        deploy.validate_platform()
        os.umask(0o022)
        if job["target"] == "project" and job["operation"] == "upgrade":
            message = execute(job)
        else:
            with deploy.deployment_lock():
                message = execute(job)
    except (ValueError, RuntimeError) as exc:
        job_write(dict(job, state="failed", message=str(exc)[:1800]))
        return 1
    except subprocess.TimeoutExpired:
        job_write(dict(job, state="failed", message="系统命令执行超时。"))
        return 1
    except Exception:
        job_write(dict(job, state="failed", message="操作失败，请查看 chennixvpn-operation.service 的系统日志。"))
        raise
    job_write(dict(job, state="succeeded", message=message))
    return 0


def version_status(target):
    version = deploy.CURRENT / "VERSION" if target == "project" else deploy.ETC / f"{target}.version"
    installed = deploy.read_text(version) or None
    try:
        latest = release(target)["tag_name"]
    except (RuntimeError, ValueError, OSError) as exc:
        return dict(installed=installed, latest=None, error=str(exc))
    return dict(installed=installed, latest=latest, error=None)


def dispatch(request):
    if not isinstance(request, dict):
        raise RequestError("需要 JSON 对象。")
    action = request.get("action")
    if action == "start":
        return enqueue(request)
    if action == "job":
        return status_view(job_read(request.get("id")))
    if action == "jobs":
        return list_jobs()
    if action == "versions":
        with ThreadPoolExecutor(max_workers=len(TARGETS)) as pool:
            return dict(zip(TARGETS, pool.map(version_status, TARGETS)))
    if action == "installed-versions":
        return installed_versions()
    raise RequestError("无效的请求。")


def main():
    if os.geteuid():
        return 1
    if len(sys.argv) == 3 and sys.argv[1] == "--run":
        return work(sys.argv[2])
    if len(sys.argv) != 1:
        return 2
    try:
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise RequestError("请求过大。", 413)
        result = dispatch(json.loads(raw))
    except RequestError as exc:
        result = {"error": str(exc), "status": exc.status}
    except (TypeError, ValueError) as exc:
        result = {"error": str(exc), "status": 400}
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        result = {"error": "无法执行系统操作，请查看面板服务日志。", "status": 503}
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
