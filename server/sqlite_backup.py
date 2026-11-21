"""Stream a consistent panel database backup as the unprivileged database owner."""
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path


def copy_database(source, destination):
    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as reader:
        with closing(sqlite3.connect(destination)) as writer:
            reader.backup(writer)


def transfer(action, database, stream):
    with tempfile.TemporaryDirectory(prefix="chennixvpn-sqlite-") as temp:
        snapshot = Path(temp) / "snapshot.db"
        if action == "save":
            if database.exists():
                copy_database(database, snapshot)
                with snapshot.open("rb") as file:
                    shutil.copyfileobj(file, stream)
        elif action == "restore":
            with snapshot.open("wb") as file:
                shutil.copyfileobj(stream, file)
            if snapshot.stat().st_size:
                copy_database(snapshot, database)
            else:
                # An empty backup records that no database existed before the switch.
                for suffix in ("-wal", "-shm", "-journal", ""):
                    Path(str(database) + suffix).unlink(missing_ok=True)
        else:
            raise ValueError("Unknown database backup operation")


if __name__ == "__main__":
    action, path = sys.argv[1:]
    transfer(action, Path(path), sys.stdout.buffer if action == "save" else sys.stdin.buffer)
