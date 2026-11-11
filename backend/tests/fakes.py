"""Test doubles only. Never selectable by application deployment configuration."""
class MemorySearch:
    def __init__(self):
        self.documents = {}
        self.unavailable = False

    def index(self, org, document):
        if self.unavailable:
            raise ConnectionError("secret should never be logged")
        assert document["tenant_id"] == org
        self.documents[org, document["id"]] = document.copy()

    def search(self, org, filters, offset, limit):
        if self.unavailable:
            raise ConnectionError("secret should never be logged")
        found = [e for (tenant, _), e in self.documents.items() if tenant == org]
        for key, value in filters.items():
            found = [e for e in found if (e["source_time"] >= value if key == "start" else e["source_time"] <= value if key == "end" else e.get(key) == value)]
        found.sort(key=lambda e: e["id"])
        found.sort(key=lambda e: e["source_time"], reverse=True)
        return {"items": found[offset:offset+limit], "total": len(found)}


class MemoryObjects:
    def __init__(self):
        self.objects = {}

    def put(self, org, key, data):
        assert key.startswith(org+"/")
        self.objects[key] = data
