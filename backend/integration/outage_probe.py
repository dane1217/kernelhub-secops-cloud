"""Disposable Compose failure drill. Never valid in staging/production."""
import json
import os
from pathlib import Path
import sys
import time
import uuid
from secops.events import now
from secops.runtime import build
from secops.service import Problem

settings, db, service = build()
if settings.environment != "development" or os.getenv("RUN_STACK_TESTS") != "1":
    raise SystemExit("This drill is restricted to an explicitly enabled development stack")
state_file = Path("/tmp/secops-outage-probe.json")

if sys.argv[1] == "prepare":
    identity = "outage-drill-"+str(uuid.uuid4())
    admin = service.register_identity(identity,identity+"@example.test",identity)
    org = service.organization_create(admin,"Synthetic outage/restart drill")
    source = service.source_create(admin,org["id"],org["workspace_id"],"Synthetic outage source","normalized")
    payload = [{"event_id":"outage-event","timestamp":now(),"action":"log.clear","host":"synthetic-outage","synthetic":True}]
    result = service.ingest(source["credential"],payload)
    assert result["accepted"] == 1
    assert service.ingest(source["credential"],payload)["duplicates"] == 1
    try:
        service.event_search(admin,org["id"],{})
    except Problem as exc:
        assert exc.status == 503
    else:
        raise AssertionError("Search must actually be unavailable during this drill")
    service.process_one()
    with db.transaction() as tx:
        job = tx.one("SELECT status FROM outbox WHERE org_id=? AND event_id=?",(org["id"],result["event_ids"][0]))
        assert job["status"] == "pending"
    state_file.write_text(json.dumps({"subject":identity,"org":org["id"]}),encoding="utf-8")
    print("Accepted and retained one deduplicated event while real search was stopped.")
elif sys.argv[1] == "recover":
    state = json.loads(state_file.read_text())
    admin = service.register_identity(state["subject"],state["subject"]+"@example.test")
    recovered = False
    for _ in range(120):
        try:
            found = service.event_search(admin,state["org"],{})
            alerts = service.alert_list(admin,state["org"])
            if found["total"] == 1 and len(alerts) == 1:
                assert len(service.alert_get(admin,state["org"],alerts[0]["id"])["evidence"]) == 1
                recovered = True
                break
        except Problem as exc:
            assert exc.status == 503
        time.sleep(1)
    assert recovered,"Celery did not recover the durable job after search/worker restart"
    print("Real Celery worker recovered the event and exactly one alert after SIGKILL/restart.")
else:
    raise SystemExit("Expected prepare or recover")
