import csv
import io
import ipaddress
import math
import re
from dataclasses import dataclass

from client.cf_speedtest import REPORT_VERSION, diagnose_report, rank_candidate


REQUIRED = {
    "ip", "colo", "attempts", "successes", "tcp_ms", "median_ms", "download_mbps", "error", "download_error",
    "report_version", "target_fingerprint", "measured_at",
    "baseline_attempts", "baseline_successes", "baseline_tcp_ms", "baseline_median_ms", "baseline_error", "baseline_colo",
}


@dataclass(frozen=True)
class Report:
    rows: list[dict]
    target_fingerprint: str
    measured_at: int
    baseline: dict
    diagnosis: list[str]


def colo_value(text):
    value = (text or "").strip().upper()
    if value and not re.fullmatch(r"[A-Z]{3}", value):
        raise ValueError
    return value


def optional_ms(text):
    if text is None:
        raise ValueError
    value = float(text) if text else None
    if value is not None and (not math.isfinite(value) or value < 0):
        raise ValueError
    return value


def measurement(attempts_text, successes_text, tcp_text, median_text):
    attempts, successes = int(attempts_text), int(successes_text)
    tcp_ms = optional_ms(tcp_text)
    median_ms = optional_ms(median_text)
    if not 1 <= attempts <= 1000000 or not 0 <= successes <= attempts or (successes and median_ms is None):
        raise ValueError
    return attempts, successes, tcp_ms, median_ms


def parse_report_with_metadata(text):
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff"), newline=""), strict=True)
    if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames) or len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("请选择 v0.2.0 客户端生成的测速报告 CSV（*-report.csv）")
    rows = []
    seen = set()
    metadata = None
    baseline = None
    for row in reader:
        try:
            if None in row:
                raise ValueError
            ip = str(ipaddress.ip_address(row["ip"]))
            if ip in seen or "%" in ip:
                raise ValueError
            colo = colo_value(row["colo"])
            attempts, ok, tcp_ms, ms = measurement(row["attempts"], row["successes"], row["tcp_ms"], row["median_ms"])
            speed = float(row["download_mbps"]) if row["download_mbps"] else None
            if speed is not None and (not math.isfinite(speed) or speed < 0):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"CSV 第 {reader.line_num} 行数据无效或 IP 重复") from None

        version, target, measured_at = (row[key] or "" for key in ("report_version", "target_fingerprint", "measured_at"))
        if (version != REPORT_VERSION or not re.fullmatch(r"[0-9a-f]{64}", target)
                or not re.fullmatch(r"[0-9]{1,12}", measured_at) or not 0 < int(measured_at) <= 253402300799):
            raise ValueError(f"CSV 第 {reader.line_num} 行测速目标、版本或测量时间无效")
        current = (target, int(measured_at))
        if metadata is not None and metadata != current:
            raise ValueError("同一份 CSV 的测速目标和测量时间须一致")
        metadata = current

        try:
            original_attempts, original_successes, original_tcp_ms, original_ms = measurement(
                row["baseline_attempts"], row["baseline_successes"], row["baseline_tcp_ms"], row["baseline_median_ms"])
            baseline_colo = colo_value(row["baseline_colo"])
        except (ValueError, TypeError):
            raise ValueError(f"CSV 第 {reader.line_num} 行原始入口对照无效") from None
        original = dict(attempts=original_attempts, successes=original_successes, tcp_ms=original_tcp_ms,
                        median_ms=original_ms, error=row["baseline_error"], colo=baseline_colo)
        if baseline is not None and baseline != original:
            raise ValueError("同一份 CSV 的原始入口对照须一致")
        baseline = original

        seen.add(ip)
        rows.append(dict(ip=ip, colo=colo, attempts=attempts, successes=ok, tcp_ms=tcp_ms, median_ms=ms,
                         download_mbps=speed, error=row["error"][:200], download_error=row["download_error"][:200]))
        if len(rows) > 4096:
            raise ValueError("每份报告最多支持 4096 行")
    if not rows:
        raise ValueError("CSV 里没有候选地址")
    rows.sort(key=lambda r: rank_candidate(
        r["ip"], r["attempts"], r["successes"], r["median_ms"], r["download_mbps"], r["tcp_ms"]))
    baseline["error"] = baseline["error"][:200]
    return Report(rows, *metadata, baseline=baseline, diagnosis=diagnose_report(rows, baseline))
