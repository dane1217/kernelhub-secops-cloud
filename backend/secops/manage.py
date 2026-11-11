"""Explicit migration and reindex commands; never run DDL on API startup."""
import argparse
import os
import json
from .db import Database


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["migrate", "reindex"])
    args = parser.parse_args()
    db = Database(os.environ["DATABASE_URL"])
    if args.command == "migrate":
        db.migrate()
        if db.postgres:
            with db.transaction() as tx:
                tx.execute("REVOKE ALL ON schema_migrations FROM secops_app")
                tx.execute("REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON audit FROM secops_app")
    else:
        from .runtime import build
        _, _, service = build()
        cursor = ""
        while True:
            with db.transaction() as tx:
                rows = tx.all("SELECT id,org_id,document FROM events WHERE id>? ORDER BY id LIMIT 100", (cursor,))
            if not rows:
                break
            for row in rows:
                service.search.index(row["org_id"], json.loads(row["document"]))
                cursor = row["id"]


if __name__ == "__main__":
    main()
