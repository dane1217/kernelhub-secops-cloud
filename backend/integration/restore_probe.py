"""Compare a fresh logical PostgreSQL restore with the disposable CI source."""
import json
import os
from urllib.parse import urlsplit,urlunsplit
from secops.config import Settings
from secops.db import Database

settings = Settings().validate()
if settings.environment != "development" or os.getenv("RUN_STACK_TESTS") != "1":
    raise SystemExit("This drill is restricted to an explicitly enabled development stack")
source = Database(settings.database_url)
parts = urlsplit(settings.database_url)
restored = Database(urlunsplit(parts._replace(path="/secops_restore_check")))
tables = ("organizations","workspaces","memberships","events","outbox","alerts","incidents","incident_alerts","incident_entries","audit")
with source.transaction() as a, restored.transaction() as b:
    for table in tables:
        # Table identifiers are a fixed code allowlist, never input.
        assert a.one(f"SELECT COUNT(*) AS n FROM {table}")["n"] == b.one(f"SELECT COUNT(*) AS n FROM {table}")["n"],table
    for alert in b.all("SELECT org_id,evidence_ids,rule_snapshot FROM alerts LIMIT 100"):
        assert json.loads(alert["rule_snapshot"])["version"] == "1.0.0"
        for event in json.loads(alert["evidence_ids"]):
            assert b.one("SELECT id FROM events WHERE org_id=? AND id=?",(alert["org_id"],event))
try:
    with restored.transaction() as tx:
        tx.execute("UPDATE audit SET actor='forbidden-restore-test'")
except Exception:
    pass
else:
    raise AssertionError("Restored audit mutation protection is absent")
print("Fresh PostgreSQL logical restore matches application/evidence/audit counts and audit protection.")
