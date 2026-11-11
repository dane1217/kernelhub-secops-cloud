"""Requires installed API dependencies; runs in CI and the backend image."""
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from fastapi.testclient import TestClient
from secops.api import create_app
from secops.db import Database
from secops.service import Service, Problem, digest
from tests.fakes import MemoryObjects, MemorySearch


class ApiContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database("sqlite:///"+str(pathlib.Path(self.temp.name)/"api.sqlite"))
        self.db.migrate()
        self.s = Service(self.db, MemorySearch(), MemoryObjects())
        self.admin = self.s.register_identity("admin", "admin@example.test", "admin")
        self.org = self.s.organization_create(self.admin, "API test")
        self.key = self.s.api_credential(self.admin, self.org["id"], "org_admin")["credential"]
        owner = self
        class Sessions:
            def session(self, cookie):
                if cookie != "valid-session":
                    raise Problem(401, "sign in required")
                return owner.admin, "csrf-value", "admin@example.test"
        self.client = TestClient(create_app(self.s, Sessions(), SimpleNamespace(product_name="Test SOC",public_url="http://testserver",environment="development")))
        self.headers = {"Authorization": "Bearer "+self.key}
        self.base = f"/api/orgs/{self.org['id']}"

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def test_authenticated_http_vertical_slice_and_export(self):
        source = self.client.post(self.base+"/sources", headers=self.headers, json={"name":"JSON","kind":"normalized","workspace_id":self.org["workspace_id"]})
        self.assertEqual(201, source.status_code)
        from secops.events import now
        events = [{"event_id":str(i),"timestamp":now(),"action":"auth.failure","user":"alice","source_ip":"192.0.2.10"} for i in range(5)]
        accepted = self.client.post("/api/ingest",headers={"Authorization":"Bearer "+source.json()["credential"]},json=events)
        self.assertEqual(202, accepted.status_code)
        while self.s.process_one():
            pass
        self.assertEqual(5, self.client.get(self.base+"/events",headers=self.headers).json()["total"])
        self.assertEqual(1, len(self.client.get(self.base+"/alerts",headers=self.headers).json()))
        exported = self.client.get(self.base+"/events/export",headers=self.headers)
        self.assertEqual(5, len(exported.text.splitlines()))
        self.assertIn("events.export",str(self.s.audit_list(self.admin,self.org["id"])))

    def test_invalid_credentials_csrf_and_validation_do_not_leak_inputs(self):
        self.assertEqual(401,self.client.get(self.base+"/sources").status_code)
        self.client.cookies.set("kh_session","valid-session")
        self.assertEqual(403,self.client.post("/api/orgs",json={"name":"blocked"}).status_code)
        self.assertEqual(201,self.client.post("/api/orgs",headers={"Origin":"http://testserver","X-CSRF-Token":"csrf-value"},json={"name":"allowed"}).status_code)
        result = self.client.post(self.base+"/sources",headers=self.headers,json={"name":"secret-password-value"})
        self.assertEqual(422,result.status_code)
        self.assertNotIn("secret-password-value",result.text)
        self.assertEqual(413,self.client.post("/api/ingest",content=b"x"*(1024*1024+1)).status_code)

    def test_query_execution_is_not_exposed(self):
        self.assertEqual(422,self.client.get(self.base+"/events?query=*",headers=self.headers).status_code)
        self.assertEqual(422,self.client.get(self.base+"/events?offset=10000",headers=self.headers).status_code)
