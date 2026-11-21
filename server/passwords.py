"""Administrator credential format shared by the installer and the panel."""

import hashlib
import hmac
import secrets
import sys
from getpass import getpass


MAX_BASIC_AUTH_HEADER = 2048
MAX_PASSWORD_BYTES = (MAX_BASIC_AUTH_HEADER - len("Basic ")) // 4 * 3 - len("admin:")


def _password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()


def credentials(password):
    salt = secrets.token_bytes(16)
    return salt.hex() + ":" + _password_digest(password, salt)


def verify_password(password, credential):
    salt, expected = credential.split(":")
    return hmac.compare_digest(_password_digest(password, bytes.fromhex(salt)), expected)


def read_admin_hash(from_stdin=False):
    if from_stdin:
        if sys.stdin.isatty():
            raise ValueError("--admin-password-stdin 需要通过管道或重定向提供密码。")
        # Read at most a password, an optional CRLF and one excess byte.
        line = sys.stdin.buffer.readline(MAX_PASSWORD_BYTES + 3)
        try:
            password = line.removesuffix(b"\r\n").removesuffix(b"\n").decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("管理员密码须使用 UTF-8。") from None
    else:
        if not sys.stdin.isatty():
            raise ValueError("无人值守首装需要 --non-interactive 和 --admin-password-stdin。")
        password = getpass("管理员 admin 的新密码（至少 12 位）：")
        if password != getpass("再次输入："):
            raise ValueError("两次输入的密码不一致。")
    if len(password) < 12 or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES or any(c in password for c in "\r\n\0"):
        raise ValueError(f"管理员密码须至少 12 个字符、最多 {MAX_PASSWORD_BYTES} 个 UTF-8 字节，且为单行。")
    return credentials(password)
