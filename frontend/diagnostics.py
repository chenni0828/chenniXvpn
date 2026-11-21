import csv
import io
import ipaddress
import math
import re
from dataclasses import dataclass

from client.cf_speedtest import REPORT_VERSION, rank_candidate


METADATA = {"report_version", "target_fingerprint", "measured_at"}


@dataclass(frozen=True)
class Report:
    rows: list[dict]
    target_fingerprint: str | None
    measured_at: int | None


def parse_report(text):
    return parse_report_with_metadata(text).rows


def parse_report_with_metadata(text):
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff"), newline=""), strict=True)
    required = {"ip", "attempts", "successes", "median_ms", "download_mbps"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames) or len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("请选择本地 cf_speedtest.py 生成的 CSV")
    fields = METADATA.intersection(reader.fieldnames)
    if fields and fields != METADATA:
        raise ValueError("CSV 缺少测速目标或测量时间字段")
    rows = []
    seen = set()
    metadata = None
    for row in reader:
        try:
            ip = str(ipaddress.ip_address(row["ip"]))
            attempts, ok = int(row["attempts"]), int(row["successes"])
            if row["median_ms"] is None or row["download_mbps"] is None:
                raise ValueError
            ms = float(row["median_ms"]) if row["median_ms"] else None
            speed = float(row["download_mbps"]) if row["download_mbps"] else None
            if (None in row or ip in seen or "%" in ip or not 0 <= ok <= attempts or not 1 <= attempts <= 1000000
                    or (ok > 0 and ms is None)
                    or any(v is not None and (not math.isfinite(v) or v < 0) for v in (ms, speed))):
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
        seen.add(ip)
        rows.append(dict(ip=ip, attempts=attempts, successes=ok, median_ms=ms, download_mbps=speed,
                         error=(row.get("error") or row.get("download_error") or "")[:200]))
        if len(rows) > 4096:
            raise ValueError("每份报告最多支持 4096 行")
    if not rows:
        raise ValueError("CSV 里没有候选地址")
    rows.sort(key=lambda r: rank_candidate(r["ip"], r["attempts"], r["successes"], r["median_ms"], r["download_mbps"]))
    return Report(rows, *(metadata or (None, None)))
