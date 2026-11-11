"""Private service health probes; no secret-bearing exception details."""
import os
import sys
from .db import Database
from .events import now, parse_time


def main():
    try:
        with Database(os.environ["DATABASE_URL"]).transaction() as tx:
            row = tx.one("SELECT last_seen FROM worker_health WHERE name='scheduler'")
        if not row or (parse_time(now())-parse_time(row["last_seen"])).total_seconds() > 60:
            raise RuntimeError("stale")
    except Exception:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
