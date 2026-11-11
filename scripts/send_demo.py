"""Send explicitly synthetic telemetry with a separately created ingestion key."""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import json
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://localhost:8080")
args = parser.parse_args()
key = getpass.getpass("Source ingestion credential (hidden): ")
start = datetime.now(timezone.utc)-timedelta(seconds=60)
events = [{"event_id":f"synthetic-login-{start.isoformat()}-{i}","timestamp":(start+timedelta(seconds=i)).isoformat(),
           "action":"auth.failure","host":"synthetic-host","user":"synthetic-user","source_ip":"192.0.2.10","synthetic":True} for i in range(5)]
events.append({**events[-1],"event_id":events[-1]["event_id"]+"-success","action":"auth.success","timestamp":(start+timedelta(seconds=10)).isoformat()})
request = urllib.request.Request(args.url.rstrip("/")+"/api/ingest", data=json.dumps(events).encode(),
    headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},method="POST")
with urllib.request.urlopen(request,timeout=15) as response:
    print(response.read().decode())
