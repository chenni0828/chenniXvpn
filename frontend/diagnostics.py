import csv
import io
import ipaddress
import math
import re
from dataclasses import dataclass

from client.cf_speedtest import REPORT_VERSION, diagnose_report, rank_candidate


METADATA = {"report_version", "target_fingerprint", "measured_at"}
BASELINE_FIELDS = {"baseline_attempts", "baseline_successes", "baseline_median_ms", "baseline_error"}


@dataclass(frozen=True)
class Report:
    rows: list[dict]
    target_fingerprint: str | None
    measured_at: int | None
    baseline: dict | None = None
    diagnosis: list[str] | None = None


def colo_value(text):
    value = (text or "").strip().upper()
    if value and not re.fullmatch(r"[A-Z]{3}", value):
        raise ValueError
    return value


def parse_report(text):
    return parse_report_with_metadata(text).rows


def measurement(attempts_text, successes_text, median_text):
    if median_text is None:
        raise ValueError
    attempts, successes = int(attempts_text), int(successes_text)
    median_ms = float(median_text) if median_text else None
    if (not 1 <= attempts <= 1000000 or not 0 <= successes <= attempts
            or (successes and median_ms is None)
            or (median_ms is not None and (not math.isfinite(median_ms) or median_ms < 0))):
        raise ValueError
    return attempts, successes, median_ms


def parse_report_with_metadata(text):
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff"), newline=""), strict=True)
    required = {"ip", "attempts", "successes", "median_ms", "download_mbps"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames) or len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("请选择客户端生成的测速报告 CSV（*-report.csv）")
    fields = METADATA.intersection(reader.fieldnames)
    if fields and fields != METADATA:
        raise ValueError("CSV 缺少测速目标或测量时间字段")
    baseline_fields = BASELINE_FIELDS.intersection(reader.fieldnames)
    if baseline_fields and (baseline_fields != BASELINE_FIELDS or not fields):
        raise ValueError("CSV 的原始入口对照字段不完整")
    rows = []
    seen = set()
    metadata = None
    baseline = None
    for row in reader:
        try:
            ip = str(ipaddress.ip_address(row["ip"]))
            colo = colo_value(row.get("colo"))
            attempts, ok, ms = measurement(row["attempts"], row["successes"], row["median_ms"])
            if None in row or ip in seen or "%" in ip or row["download_mbps"] is None:
                raise ValueError
            speed = float(row["download_mbps"]) if row["download_mbps"] else None
            if speed is not None and (not math.isfinite(speed) or speed < 0):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"CSV 第 {reader.line_num} 行数据无效或 IP 重复") from None
        if fields:
            version, target, measured_at = (row[key] or "" for key in ("report_version", "target_fingerprint", "measured_at"))
            if (version != REPORT_VERSION or not re.fullmatch(r"[0-9a-f]{64}", target)
                    or not re.fullmatch(r"[0-9]{1,12}", measured_at) or not 0 < int(measured_at) <= 253402300799):
                raise ValueError(f"CSV 第 {reader.line_num} 行测速目标、版本或测量时间无效")
            current = (target, int(measured_at))
            if metadata is not None and metadata != current:
                raise ValueError("同一份 CSV 的测速目标和测量时间须一致")
            metadata = current
        if baseline_fields:
            try:
                original_attempts, original_successes, original_ms = measurement(
                    row["baseline_attempts"], row["baseline_successes"], row["baseline_median_ms"])
                if row["baseline_error"] is None:
                    raise ValueError
                baseline_colo = colo_value(row.get("baseline_colo"))
            except (ValueError, TypeError):
                raise ValueError(f"CSV 第 {reader.line_num} 行原始入口对照无效") from None
            original = dict(attempts=original_attempts, successes=original_successes, median_ms=original_ms,
                            error=row["baseline_error"], colo=baseline_colo)
            if baseline is not None and baseline != original:
                raise ValueError("同一份 CSV 的原始入口对照须一致")
            baseline = original
        seen.add(ip)
        rows.append(dict(ip=ip, colo=colo, attempts=attempts, successes=ok, median_ms=ms, download_mbps=speed,
                         error=(row.get("error") or "")[:200], download_error=(row.get("download_error") or "")[:200]))
        if len(rows) > 4096:
            raise ValueError("每份报告最多支持 4096 行")
    if not rows:
        raise ValueError("CSV 里没有候选地址")
    rows.sort(key=lambda r: rank_candidate(r["ip"], r["attempts"], r["successes"], r["median_ms"], r["download_mbps"]))
    if baseline is not None:
        baseline["error"] = baseline["error"][:200]
    return Report(rows, *(metadata or (None, None)), baseline=baseline, diagnosis=diagnose_report(rows, baseline))
