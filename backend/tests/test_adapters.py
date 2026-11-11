import unittest
import uuid
from secops.adapters import OpenSearch, S3Objects


class AdapterIsolation(unittest.TestCase):
    def test_search_index_and_query_both_bind_tenant(self):
        org = str(uuid.uuid4())
        adapter = OpenSearch("https://search.example.test")
        calls = []
        def call(path, method="GET", data=None):
            calls.append((path, data))
            return {"hits": {"hits": [], "total": {"value": 0}}}
        adapter.call = call
        adapter.search(org, {"user": "alice"}, 0, 50)
        path, body = calls[0]
        self.assertEqual(f"/kh-events-{org}/_search", path)
        self.assertIn({"term": {"tenant_id": org}}, body["query"]["bool"]["filter"])
        with self.assertRaises(ValueError):
            adapter.search("../../_all", {}, 0, 50)
        with self.assertRaises(ValueError):
            adapter.search(org, {"query": "*"}, 0, 50)

    def test_objects_reject_cross_tenant_and_traversal(self):
        adapter = object.__new__(S3Objects)
        org, other = str(uuid.uuid4()), str(uuid.uuid4())
        with self.assertRaises(ValueError):
            adapter.put(org, other+"/raw.json", b"test")
        with self.assertRaises(ValueError):
            adapter.put(org, org+"/../raw.json", b"test")
