"""Production adapters. No tenant identifier is ever interpolated without validation."""
import base64
import json
import ssl
import urllib.error
import urllib.request
import uuid


def tenant(value):
    return str(uuid.UUID(value))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, method="GET", data=None, headers=None, ca=None):
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with opener.open(request, timeout=5) as response:
        content = response.read(4*1024*1024)
        return json.loads(content) if content else {}


class OpenSearch:
    def __init__(self, url, username="", password="", ca=None):
        self.url, self.ca = url.rstrip("/"), ca
        self.headers = {"Content-Type": "application/json"}
        if username:
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    def call(self, suffix, method="GET", data=None):
        return request_json(self.url+suffix, method, json.dumps(data).encode() if data is not None else None, self.headers, self.ca)

    def index(self, org, document):
        org = tenant(org)
        if document["tenant_id"] != org:
            raise ValueError("tenant mismatch")
        name = "kh-events-"+org
        try:
            self.call("/"+name, "PUT", {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                       "mappings": {"dynamic": "strict", "properties": {
                           **{k: {"type": "keyword", "ignore_above": 512} for k in (
                               "id", "tenant_id", "workspace_id", "source_id", "external_id", "action", "category", "host", "user", "outcome", "severity", "schema_version", "parser_version", "raw_ref", "data_mode")},
                           "source_ip": {"type": "ip"}, "destination_ip": {"type": "ip"},
                           "source_time": {"type": "date"}, "received_at": {"type": "date"},
                           "historical": {"type": "boolean"}, "command_line": {"type": "text", "index": False}}}})
        except urllib.error.HTTPError as exc:
            if exc.code != 400:
                raise
            # 400 can also mean an invalid mapping, so verify the index really exists.
            self.call("/"+name)
        self.call(f"/{name}/_doc/{uuid.UUID(document['id'])}?refresh=wait_for", "PUT", document)

    def search(self, org, filters, offset, limit):
        org = tenant(org)
        query = [{"term": {"tenant_id": org}}]
        for key, value in filters.items():
            if key not in ("start", "end"):
                if key not in ("action", "host", "user", "source_ip", "severity", "source_id"):
                    raise ValueError("unsupported filter")
                query.append({"term": {key: value}})
        if filters.get("start") or filters.get("end"):
            query.append({"range": {"source_time": {**({"gte": filters["start"]} if filters.get("start") else {}),
                                                     **({"lte": filters["end"]} if filters.get("end") else {})}}})
        try:
            result = self.call(f"/kh-events-{org}/_search", "POST", {
                "query": {"bool": {"filter": query}}, "from": offset, "size": limit,
                "sort": [{"source_time": "desc"}, {"id": "asc"}], "track_total_hits": True})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"items": [], "total": 0}
            raise
        return {"items": [h["_source"] for h in result["hits"]["hits"]], "total": result["hits"]["total"]["value"]}

    def health(self):
        self.call("/_cluster/health")


class S3Objects:
    def __init__(self, bucket, endpoint=None, encrypted=True):
        import boto3
        from botocore.config import Config
        self.bucket, self.encrypted = bucket, encrypted
        self.client = boto3.client("s3", endpoint_url=endpoint or None, config=Config(
            connect_timeout=3, read_timeout=5, retries={"max_attempts": 2}, s3={"addressing_style": "path"}))

    def put(self, org, key, content):
        if not key.startswith(tenant(org)+"/") or ".." in key:
            raise ValueError("object tenant mismatch")
        extra = {"ServerSideEncryption": "AES256"} if self.encrypted else {}
        self.client.put_object(Bucket=self.bucket, Key=key, Body=content, ContentType="application/json", **extra)

    def health(self):
        self.client.head_bucket(Bucket=self.bucket)
