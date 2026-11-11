import json
from datetime import timedelta
import pathlib
import sqlite3
import tempfile
import unittest

from secops.db import Database
from secops.events import InvalidEvent, normalize, now, parse_time
from secops.service import Problem, Service, digest
from tests.fakes import MemoryObjects, MemorySearch


class Workflows(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database("sqlite:///"+str(pathlib.Path(self.temp.name)/"test.sqlite"))
        self.db.migrate()
        self.search, self.objects = MemorySearch(), MemoryObjects()
        self.s = Service(self.db, self.search, self.objects)
        self.admin = self.s.register_identity("administrator", "admin@example.test", "administrator")
        self.a = self.s.organization_create(self.admin, "Tenant A")
        self.b = self.s.organization_create(self.admin, "Tenant B")
        self.a_source = self.s.source_create(self.admin, self.a["id"], self.a["workspace_id"], "A source", "normalized")
        self.b_source = self.s.source_create(self.admin, self.b["id"], self.b["workspace_id"], "B source", "normalized")
        self.viewer = self.s.register_identity("viewer", "viewer@example.test")
        invite = self.s.invite(self.admin, self.b["id"], "viewer@example.test", "viewer")
        self.s.accept_invite(self.viewer, invite["invitation"])

    def tearDown(self):
        self.temp.cleanup()

    def events(self, action="auth.failure", count=5, **overrides):
        base = parse_time(now())-timedelta(seconds=60)
        return [{"event_id": f"{action}-{i}", "timestamp": (base+timedelta(seconds=i)).isoformat(),
                 "action": action, "user": "alice", "source_ip": "192.0.2.10", "host": "pilot-host", **overrides}
                for i in range(count)]

    def drain(self):
        while self.s.process_one():
            pass

    def deny(self, fn, status=403):
        with self.assertRaises(Problem) as result:
            fn()
        self.assertEqual(status, result.exception.status)

    def test_acceptance_ingest_search_detection_resolve_audit(self):
        result = self.s.ingest(self.a_source["credential"], self.events())
        self.assertEqual(5, result["accepted"])
        self.drain()
        found = self.s.event_search(self.admin, self.a["id"], {})
        self.assertEqual(5, found["total"])
        alerts = self.s.alert_list(self.admin, self.a["id"])
        self.assertEqual(["KH-001"], [a["rule_id"] for a in alerts])
        detail = self.s.alert_get(self.admin, self.a["id"], alerts[0]["id"])
        self.assertEqual(5, len(detail["evidence"]))
        self.assertEqual("1.0.0", detail["rule"]["version"])
        incident = self.s.incident_create(self.admin, self.a["id"], "Investigate login failures", "high", [alerts[0]["id"]])
        self.s.incident_entry(self.admin, self.a["id"], incident["id"], "note", "User confirmed activity")
        for status in ("triaging", "investigating", "resolved", "closed"):
            self.s.incident_update(self.admin, self.a["id"], incident["id"], status, "benign_activity", "Verified with user")
        item = self.s.incident_get(self.admin, self.a["id"], incident["id"])
        self.assertEqual("closed", item["status"])
        self.assertEqual(6, len(item["timeline"]))
        actions = {a["action"] for a in self.s.audit_list(self.admin, self.a["id"])}
        self.assertTrue({"organization.create", "source.create", "ingestion.accept", "alert.create", "incident.create", "incident.transition"} <= actions)

    def test_tenant_isolation_across_resources(self):
        ids = self.s.ingest(self.a_source["credential"], self.events())["event_ids"]
        self.drain()
        alert = self.s.alert_list(self.admin, self.a["id"])[0]["id"]
        incident = self.s.incident_create(self.admin, self.a["id"], "A incident", "high", [alert])["id"]
        for fn in (
            lambda: self.s.event_search(self.viewer, self.a["id"], {}),
            lambda: self.s.event_get(self.viewer, self.a["id"], ids[0], True),
            lambda: self.s.alert_get(self.viewer, self.a["id"], alert),
            lambda: self.s.incident_get(self.viewer, self.a["id"], incident),
            lambda: self.s.audit_list(self.viewer, self.a["id"]),
            lambda: self.s.overview(self.viewer, self.a["id"]),
            lambda: self.s.rule_list(self.viewer, self.a["id"]),
            lambda: self.s.sources(self.viewer, self.a["id"]),
            lambda: self.s.members(self.viewer, self.a["id"]),
            lambda: self.s.workspaces(self.viewer, self.a["id"]),
        ):
            self.deny(fn)
        self.assertEqual([], self.s.event_search(self.viewer, self.b["id"], {})["items"])
        self.deny(lambda: self.s.event_get(self.viewer, self.b["id"], ids[0]), 404)
        self.deny(lambda: self.s.alert_get(self.viewer, self.b["id"], alert), 404)
        self.deny(lambda: self.s.incident_get(self.viewer, self.b["id"], incident), 404)
        self.deny(lambda: self.s.incident_create(self.admin, self.b["id"], "Cross tenant", "high", [alert]), 404)
        self.deny(lambda: self.s.source_create(self.admin, self.b["id"], self.a["workspace_id"], "Invalid", "linux"), 422)
        self.assertTrue(all(k.startswith(self.a["id"]+"/") for k in self.objects.objects))

    def test_viewer_cannot_mutate_and_platform_admin_not_global_analyst(self):
        self.deny(lambda: self.s.source_create(self.viewer, self.b["id"], self.b["workspace_id"], "denied", "linux"))
        admin2 = self.s.register_identity("second-admin", "other@example.test", "second-admin")
        self.deny(lambda: self.s.event_search(admin2, self.a["id"], {}))

    def test_scoped_api_credential_and_membership_revocation(self):
        key = self.s.api_credential(self.admin, self.a["id"], "viewer")["credential"]
        p = self.s.authenticate_api(key)
        self.deny(lambda: self.s.sources(p, self.b["id"]))
        self.deny(lambda: self.s.source_create(p, self.a["id"], self.a["workspace_id"], "denied", "linux"))
        self.deny(lambda: self.s.authenticate_api(self.a_source["credential"]), 401)
        self.deny(lambda: self.s.ingest(key, self.events()), 401)

    def test_invalid_malformed_and_tenant_spoofing(self):
        self.deny(lambda: self.s.ingest("invalid", self.events()), 401)
        for events in ([], [{}], self.events(tenant_id=self.b["id"]), self.events(source_ip="localhost")):
            self.deny(lambda: self.s.ingest(self.a_source["credential"], events), 422)
        self.assertEqual(3, self.s.sources(self.admin, self.a["id"])[0]["parser_failures"])
        self.assertEqual(0, self.s.overview(self.admin, self.a["id"])["events"]["total"])

    def test_duplicate_delivery_and_worker_retry(self):
        a = self.s.ingest(self.a_source["credential"], self.events())
        b = self.s.ingest(self.a_source["credential"], self.events())
        self.assertEqual(a["event_ids"], b["event_ids"])
        self.assertEqual(5, b["duplicates"])
        self.drain()
        # Simulate crash after indexing/detection but before outbox commit acknowledgement.
        with self.db.transaction() as tx:
            tx.execute("UPDATE outbox SET status='pending'")
        self.s = Service(self.db, self.search, self.objects)
        self.drain()
        self.assertEqual(1, len(self.s.alert_list(self.admin, self.a["id"])))
        self.assertEqual(5, len(self.objects.objects))

    def test_search_outage_keeps_accepted_events_and_recovers(self):
        self.search.unavailable = True
        self.assertEqual(5, self.s.ingest(self.a_source["credential"], self.events())["accepted"])
        self.s.process_one()
        self.deny(lambda: self.s.event_search(self.admin, self.a["id"], {}), 503)
        with self.db.transaction() as tx:
            job = tx.one("SELECT * FROM outbox WHERE attempts=1")
            self.assertEqual("archive_or_search_unavailable", job["last_error"])
            tx.execute("UPDATE outbox SET next_attempt=?", (now(),))
        self.search.unavailable = False
        self.drain()
        self.assertEqual(5, self.s.event_search(self.admin, self.a["id"], {})["total"])

    def test_dead_letter_replay(self):
        self.s.ingest(self.a_source["credential"], self.events(count=1))
        self.search.unavailable = True
        for _ in range(8):
            with self.db.transaction() as tx:
                tx.execute("UPDATE outbox SET next_attempt=?", (now(),))
            self.s.process_one()
        dead = self.s.dead_letters(self.admin, self.a["id"])
        self.assertEqual(1, len(dead))
        self.s.retry_dead(self.admin, self.a["id"], dead[0]["id"])
        self.search.unavailable = False
        self.drain()
        self.assertEqual(1, self.s.event_search(self.admin, self.a["id"], {})["total"])

    def test_redaction_and_credential_hashing(self):
        events = self.events(count=1, password="do-not-store", message="token=do-not-store", authorization="secret")
        self.s.ingest(self.a_source["credential"], events)
        self.drain()
        self.assertNotIn(b"do-not-store", b"".join(self.objects.objects.values()))
        with self.db.transaction() as tx:
            raw = tx.one("SELECT raw_json FROM events")["raw_json"]
            self.assertNotIn("do-not-store", raw)
            self.assertEqual(digest(self.a_source["credential"]), tx.one("SELECT token_hash FROM credentials WHERE source_id=?", (self.a_source["id"],))["token_hash"])

    def test_rate_quota_and_revocation(self):
        with self.db.transaction() as tx:
            tx.execute("UPDATE organizations SET rate_minute=2 WHERE id=?", (self.a["id"],))
        self.deny(lambda: self.s.ingest(self.a_source["credential"], self.events()), 429)
        with self.db.transaction() as tx:
            tx.execute("UPDATE organizations SET rate_minute=1000,quota_daily=2 WHERE id=?", (self.a["id"],))
        self.deny(lambda: self.s.ingest(self.a_source["credential"], self.events()), 429)
        self.assertEqual(0, self.s.overview(self.admin, self.a["id"])["events"]["total"])
        self.s.source_revoke(self.admin, self.a["id"], self.a_source["id"])
        self.deny(lambda: self.s.ingest(self.a_source["credential"], self.events()), 401)

    def test_invitation_verified_email_binding_and_replay(self):
        invite = self.s.invite(self.admin, self.a["id"], "viewer@example.test", "analyst")
        self.deny(lambda: self.s.accept_invite(self.admin, invite["invitation"]))
        self.s.accept_invite(self.viewer, invite["invitation"])
        self.deny(lambda: self.s.accept_invite(self.viewer, invite["invitation"]))
        self.s.remove_member(self.admin, self.a["id"], self.viewer.user_id)
        self.deny(lambda: self.s.sources(self.viewer, self.a["id"]))

    def test_rule_tuning_and_audit_immutability(self):
        self.s.rule_update(self.admin, self.a["id"], "KH-001", False, [])
        self.s.ingest(self.a_source["credential"], self.events())
        self.drain()
        self.assertEqual([], self.s.alert_list(self.admin, self.a["id"]))
        for command in ("UPDATE audit SET actor='attacker'", "DELETE FROM audit"):
            with self.assertRaises(sqlite3.IntegrityError):
                with self.db.transaction() as tx:
                    tx.execute(command)

    def test_invalid_incident_transition(self):
        self.s.ingest(self.a_source["credential"], self.events())
        self.drain()
        alert = self.s.alert_list(self.admin, self.a["id"])[0]["id"]
        incident = self.s.incident_create(self.admin, self.a["id"], "Review", "high", [alert])["id"]
        self.deny(lambda: self.s.incident_update(self.admin, self.a["id"], incident, "closed", "true_positive"), 409)

    def test_late_failure_triggers_success_sequence(self):
        failures = self.events()
        success = self.events("auth.success", 1)[0]
        success["timestamp"] = (parse_time(failures[-1]["timestamp"])+timedelta(seconds=5)).isoformat()
        self.s.ingest(self.a_source["credential"], [success])
        self.drain()
        self.s.ingest(self.a_source["credential"], failures)
        self.drain()
        ids = {r["rule_id"] for r in self.s.alert_list(self.admin, self.a["id"])}
        self.assertTrue({"KH-001", "KH-002"} <= ids)


if __name__ == "__main__":
    unittest.main()
