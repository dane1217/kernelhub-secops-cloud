"""Real PostgreSQL/OpenSearch/S3 integration. Run only in Docker's private network."""
import os
import unittest
import uuid
from secops.events import now


@unittest.skipUnless(os.getenv("RUN_STACK_TESTS") == "1", "requires the real Compose services")
class ContainerPipeline(unittest.TestCase):
    def test_real_persistence_index_archive_detection_and_isolation(self):
        from secops.runtime import build
        _, db, service = build()
        identity = "stack-test-"+str(uuid.uuid4())
        admin = service.register_identity(identity,identity+"@example.test",identity)
        org = service.organization_create(admin,"Synthetic integration test")
        other = service.organization_create(admin,"Isolation integration test")
        source = service.source_create(admin,org["id"],org["workspace_id"],"Synthetic test source","normalized")
        payload = [{"event_id":str(i),"timestamp":now(),"action":"auth.failure","host":"synthetic-integration","user":"alice","source_ip":"192.0.2.10","synthetic":True} for i in range(5)]
        result = service.ingest(source["credential"],payload)
        for _ in range(100):
            if not service.process_one():
                break
        found = service.event_search(admin,org["id"],{})
        self.assertEqual(5,found["total"])
        self.assertEqual(0,service.event_search(admin,other["id"],{})["total"])
        alert = service.alert_list(admin,org["id"])[0]
        self.assertEqual(5,len(service.alert_get(admin,org["id"],alert["id"])["evidence"]))
        with db.transaction() as tx:
            for event_id in result["event_ids"]:
                row = tx.one("SELECT raw_key FROM events WHERE org_id=? AND id=?",(org["id"],event_id))
                service.objects.client.head_object(Bucket=service.objects.bucket,Key=row["raw_key"])
