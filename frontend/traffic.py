"""Linux interface counters and persistent, Beijing-calendar-month accounting."""
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ZONE = timezone(timedelta(hours=8))
NET = Path("/sys/class/net")
REPORTS_SCHEMA = """
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT, name TEXT, ts REAL,
        count INTEGER, usable INTEGER, best_ms REAL, rows_json TEXT, measured_at INTEGER
    )
"""


class Store:
    def __init__(self, path):
        self.path = path
        with self.db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY, iface TEXT, budget INTEGER, since REAL);
                INSERT OR IGNORE INTO settings VALUES(1,'',10000000000000,NULL);
                CREATE TABLE IF NOT EXISTS baseline(id INTEGER PRIMARY KEY, iface TEXT, boot TEXT, idx INTEGER, ts REAL, rx INTEGER, tx INTEGER);
                CREATE TABLE IF NOT EXISTS points(ts REAL PRIMARY KEY, rx_bps REAL, tx_bps REAL);
                CREATE TABLE IF NOT EXISTS months(month TEXT PRIMARY KEY, rx INTEGER, tx INTEGER);
                CREATE TABLE IF NOT EXISTS entries(node TEXT, kind TEXT, address TEXT, PRIMARY KEY(node,kind));
                CREATE TABLE IF NOT EXISTS disabled_vless_entries(kind TEXT PRIMARY KEY);
            """)
            db.execute("BEGIN IMMEDIATE")
            db.execute(REPORTS_SCHEMA)
            schema = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='reports'").fetchone()[0]
            if "AUTOINCREMENT" not in schema.upper():
                columns = {column["name"] for column in db.execute("PRAGMA table_info(reports)")}
                measured_at = "measured_at" if "measured_at" in columns else "NULL"
                db.execute("ALTER TABLE reports RENAME TO old_reports")
                db.execute(REPORTS_SCHEMA)
                db.execute(f"""
                    INSERT INTO reports(id,node,name,ts,count,usable,best_ms,rows_json,measured_at)
                    SELECT id,node,name,ts,count,usable,best_ms,rows_json,{measured_at} FROM old_reports
                """)
                db.execute("DROP TABLE old_reports")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def configure(self, iface, budget):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT iface FROM settings").fetchone()[0] != iface:
                db.execute("DELETE FROM baseline")
                db.execute("DELETE FROM points")
            db.execute("UPDATE settings SET iface=?,budget=? WHERE id=1", (iface, budget))

    def sample(self, configured, iface, boot, idx, now, rx, tx, boot_time=None):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT iface FROM settings").fetchone()[0] != configured:
                return
            prev = db.execute("SELECT * FROM baseline").fetchone()
            if prev and now <= prev["ts"]:
                return
            rx_rate = tx_rate = None
            start = None
            if prev and prev["iface"] == iface:
                if (prev["boot"], prev["idx"]) == (boot, idx) and rx >= prev["rx"] and tx >= prev["tx"]:
                    start = prev["ts"]
                    dr, dt = rx - prev["rx"], tx - prev["tx"]
                    if now - start <= 20:
                        rx_rate, tx_rate = dr * 8 / (now - start), dt * 8 / (now - start)
                elif prev["boot"] != boot and boot_time is not None and prev["ts"] <= boot_time < now:
                    start = boot_time
                    dr, dt = rx, tx
                    if now - start <= 20:
                        rx_rate, tx_rate = dr * 8 / (now - start), dt * 8 / (now - start)
            if start is not None:
                self._add_usage(db, start, now, dr, dt)
            db.execute("UPDATE settings SET since=COALESCE(since,?)", (now,))
            db.execute("INSERT OR REPLACE INTO baseline VALUES(1,?,?,?,?,?,?)", (iface, boot, idx, now, rx, tx))
            db.execute("INSERT OR REPLACE INTO points VALUES(?,?,?)", (now, rx_rate, tx_rate))
            db.execute("DELETE FROM points WHERE ts<? OR ts>?", (now - 900, now))

    @staticmethod
    def _add_usage(db, start, end, rx, tx):
        cursor = start
        counted_rx = counted_tx = 0
        while cursor < end:
            date = datetime.fromtimestamp(cursor, ZONE)
            next_month = (date.replace(day=1, hour=0, minute=0, second=0, microsecond=0) + timedelta(days=32)).replace(day=1)
            boundary = min(end, next_month.timestamp())
            fraction = (boundary - start) / (end - start)
            total_rx = rx if boundary == end else int(rx * fraction)
            total_tx = tx if boundary == end else int(tx * fraction)
            db.execute("""INSERT INTO months VALUES(?,?,?) ON CONFLICT(month) DO UPDATE SET
                       rx=rx+excluded.rx,tx=tx+excluded.tx""",
                       (date.strftime("%Y-%m"), total_rx-counted_rx, total_tx-counted_tx))
            counted_rx, counted_tx, cursor = total_rx, total_tx, boundary

    def traffic(self, available, now=None):
        now = time.time() if now is None else now
        month = datetime.fromtimestamp(now, ZONE).strftime("%Y-%m")
        with self.db() as db:
            db.execute("BEGIN")
            settings = dict(db.execute("SELECT iface,budget,since FROM settings").fetchone())
            baseline = db.execute("SELECT iface,ts FROM baseline").fetchone()
            points = [dict(r) for r in db.execute("SELECT * FROM points WHERE ts BETWEEN ? AND ? ORDER BY ts", (now-900, now))]
            months = [dict(r) for r in db.execute("SELECT * FROM months ORDER BY month DESC")]
        current = next((row for row in months if row["month"] == month), {"month": month, "rx": 0, "tx": 0})
        age = max(0.0, now - baseline["ts"]) if baseline else None
        fresh = bool(points and age is not None and age <= 20)
        return dict(settings=settings, interfaces=available, iface=baseline["iface"] if baseline else None,
                    last=baseline["ts"] if baseline else None, sample_age_s=age, points=points, fresh=fresh, current=current,
                    months=months, total_rx=sum(r["rx"] for r in months), total_tx=sum(r["tx"] for r in months))


def interfaces():
    return sorted(path.name for path in NET.glob("*") if path.name != "lo" and (path/"statistics").is_dir())


def default_iface():
    routes = []
    for line in Path("/proc/net/route").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == "00000000" and int(fields[3], 16) & 1:
            routes.append((int(fields[6]), fields[0]))
    if routes:
        return min(routes)[1]
    for line in Path("/proc/net/ipv6_route").read_text().splitlines():
        fields = line.split()
        if fields[:2] == ["0"*32, "00"] and fields[-1] != "lo":
            return fields[-1]
    raise ValueError("请选择采集网卡")


def collect(store):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    boot_time = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
    last_error = None
    while True:
        try:
            with store.db() as db:
                configured = db.execute("SELECT iface FROM settings").fetchone()[0]
            iface = configured or default_iface()
            port = NET / iface
            idx, rx, tx = (int((port/path).read_text()) for path in ("ifindex", "statistics/rx_bytes", "statistics/tx_bytes"))
            store.sample(configured, iface, boot, idx, time.time(), rx, tx, boot_time)
            last_error = None
        except (OSError, ValueError, sqlite3.Error) as exc:
            if str(exc) != last_error:
                print(f"采集失败：{exc}", flush=True)
            last_error = str(exc)
        time.sleep(5)
