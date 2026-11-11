import hmac
import json
import logging
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from .events import InvalidEvent, now, parse_time
from .rules import BY_ID, evidence_for
from .service import Problem, audit, authorize, dump


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrganizationInput(StrictModel):
    name: str = Field(min_length=1, max_length=120)


class SourceInput(OrganizationInput):
    workspace_id: str
    kind: Literal["normalized", "windows", "linux"]


class InvitationInput(StrictModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    role: Literal["org_admin", "analyst", "viewer"]


class TokenInput(StrictModel):
    credential: str = Field(min_length=20, max_length=200)


class RoleInput(StrictModel):
    role: Literal["org_admin", "analyst", "viewer"]


class TriageInput(StrictModel):
    status: Literal["new", "triaging", "escalated", "dismissed"]
    assigned_to: str | None = None


class IncidentInput(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["low", "medium", "high", "critical"]
    alerts: list[str] = Field(min_length=1, max_length=100)
    assigned_to: str | None = None


class IncidentUpdate(StrictModel):
    status: Literal["new", "triaging", "investigating", "contained", "resolved", "closed"]
    resolution: Literal["true_positive", "false_positive", "benign_activity", "insufficient_evidence"] | None = None
    summary: str = Field(default="", max_length=8000)


class EntryInput(StrictModel):
    kind: Literal["note", "task", "evidence", "feedback"]
    body: str = Field(min_length=1, max_length=8000)


class RuleInput(StrictModel):
    enabled: bool
    excluded_users: list[str] = Field(default_factory=list, max_length=100)
    suppressed_until: str | None = None
    threshold_count: int | None = Field(default=None, ge=2, le=100)


class RuleTestInput(StrictModel):
    event_ids: list[str] = Field(min_length=1, max_length=1000)


class BoundedBody:
    """Buffer at most 1 MiB, including chunked requests, before FastAPI JSON decoding."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        messages, size = [], 0
        headers = dict(scope.get("headers", []))
        if headers.get(b"content-encoding", b"identity") != b"identity":
            return await JSONResponse({"detail": "compressed requests unsupported"}, 415)(scope, receive, send)
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > 1024*1024:
                return await JSONResponse({"detail": "payload exceeds 1 MiB"}, 413)(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break
        async def replay():
            return messages.pop(0) if messages else await receive()
        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", []))+[
                    (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY")]
            await send(message)
        await self.app(scope, replay, secure_send)


def create_app(service, authentication, settings):
    app = FastAPI(title=settings.product_name, version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.add_middleware(BoundedBody)

    @app.exception_handler(Problem)
    async def problem_handler(request, exc):
        return JSONResponse({"detail": exc.message}, exc.status, headers={"Retry-After": "60"} if exc.status in (429, 503) else {})

    @app.exception_handler(InvalidEvent)
    async def event_handler(request, exc):
        return JSONResponse({"detail": str(exc)}, 422)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, exc):
        return JSONResponse({"detail": "invalid request", "fields": [".".join(map(str, e["loc"])) for e in exc.errors()]}, 422)

    @app.exception_handler(Exception)
    async def error_handler(request, exc):
        # Error IDs are safe to correlate; avoid logging customer content or integration secrets.
        error_id = str(uuid.uuid4())
        logging.getLogger("secops.api").error("request_failed", extra={"event_code": "request_failed", "error_id": error_id}, exc_info=exc)
        return JSONResponse({"detail": "service unavailable", "error_id": error_id}, 503)

    def principal(request: Request):
        header = request.headers.get("authorization", "")
        if header.startswith("Bearer "):
            return service.authenticate_api(header[7:])
        p, csrf, _ = authentication.session(request.cookies.get("kh_session"))
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("origin") != settings.public_url or not hmac.compare_digest(request.headers.get("x-csrf-token", ""), csrf):
                raise Problem(403, "CSRF verification failed")
        return p

    @app.get("/auth/login")
    def login():
        state, url = authentication.begin()
        response = RedirectResponse(url, 302)
        response.set_cookie("kh_oidc", state, httponly=True, secure=settings.environment != "development", samesite="lax", max_age=300, path="/auth")
        return response

    @app.get("/auth/callback")
    def callback(request: Request, state: str = Query(max_length=200), code: str = Query(max_length=4096)):
        token = authentication.callback(state, request.cookies.get("kh_oidc"), code)
        response = RedirectResponse("/", 302)
        response.set_cookie("kh_session", token, httponly=True, secure=settings.environment != "development", samesite="lax", max_age=1800, path="/")
        response.delete_cookie("kh_oidc", path="/auth")
        return response

    @app.post("/auth/logout")
    def logout(request: Request, p=Depends(principal)):
        authentication.logout(request.cookies.get("kh_session", ""))
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("kh_session", path="/")
        return response

    @app.get("/api/me")
    def me(request: Request, p=Depends(principal)):
        csrf, email = None, None
        if not p.scoped_org:
            _, csrf, email = authentication.session(request.cookies.get("kh_session"))
        return {"user_id": p.user_id, "platform_admin": p.platform_admin, "email": email, "csrf": csrf,
                "product_name": settings.product_name, "environment": settings.environment,
                "features": {"siem": True, "incidents": True, "soar": False, "exposure": False, "ai": False}}

    @app.get("/api/health/live")
    def live():
        return {"status": "alive"}

    @app.get("/api/branding")
    def branding():
        return {"product_name": settings.product_name, "mark": getattr(settings, "brand_mark", "K"),
                "accent": getattr(settings, "brand_accent", "#47e6bd")}

    @app.get("/internal/health/ready")
    def ready():
        with service.db.transaction() as tx:
            tx.execute("SELECT 1")
        service.search.health()
        service.objects.health()
        return {"status": "ready"}

    @app.get("/internal/metrics")
    def metrics():
        from prometheus_client import CollectorRegistry, Gauge, generate_latest
        registry = CollectorRegistry()
        with service.db.transaction() as tx:
            for state in ("pending", "dead"):
                value = tx.one("SELECT COUNT(*) AS n FROM outbox WHERE status=?", (state,))["n"]
                Gauge("secops_jobs_"+state, "Durable ingestion jobs", registry=registry).set(value)
            heartbeat = tx.one("SELECT last_seen FROM worker_health WHERE name='scheduler'")
            age = (parse_time(now())-parse_time(heartbeat["last_seen"])).total_seconds() if heartbeat else 86400
            Gauge("secops_worker_heartbeat_age_seconds", "Seconds since worker scheduler heartbeat", registry=registry).set(age)
        return Response(generate_latest(registry), media_type="text/plain")

    @app.get("/api/orgs")
    def organizations(p=Depends(principal)):
        return service.organizations(p)

    @app.post("/api/orgs", status_code=201)
    def organization_create(body: OrganizationInput, p=Depends(principal)):
        return service.organization_create(p, body.name)

    @app.get("/api/orgs/{org}/workspaces")
    def workspaces(org: str, p=Depends(principal)):
        return service.workspaces(p, org)

    @app.get("/api/orgs/{org}/members")
    def members(org: str, p=Depends(principal)):
        return service.members(p, org)

    @app.delete("/api/orgs/{org}/members/{user_id}")
    def member_remove(org: str, user_id: str, p=Depends(principal)):
        service.remove_member(p, org, user_id)
        return {"removed": True}

    @app.post("/api/orgs/{org}/invitations", status_code=201)
    def invitation(org: str, body: InvitationInput, p=Depends(principal)):
        return service.invite(p, org, body.email, body.role)

    @app.post("/api/invitations/accept")
    def invitation_accept(body: TokenInput, p=Depends(principal)):
        return service.accept_invite(p, body.credential)

    @app.post("/api/orgs/{org}/credentials", status_code=201)
    def credential(org: str, body: RoleInput, p=Depends(principal)):
        return service.api_credential(p, org, body.role)

    @app.post("/api/orgs/{org}/credentials/revoke")
    def credential_revoke(org: str, body: TokenInput, p=Depends(principal)):
        from .service import digest
        with service.db.transaction() as tx:
            authorize(tx, p, org, "org_admin")
            row = tx.execute("UPDATE credentials SET revoked=1 WHERE org_id=? AND token_hash=?", (org, digest(body.credential)))
            if row.rowcount != 1:
                raise Problem(404, "credential not found")
            audit(tx, org, p.user_id, "credential.revoke", "credential")
        return {"revoked": True}

    @app.get("/api/orgs/{org}/sources")
    def sources(org: str, p=Depends(principal)):
        return service.sources(p, org)

    @app.post("/api/orgs/{org}/sources", status_code=201)
    def source_create(org: str, body: SourceInput, p=Depends(principal)):
        return service.source_create(p, org, body.workspace_id, body.name, body.kind)

    @app.post("/api/orgs/{org}/sources/{source}/revoke")
    def source_revoke(org: str, source: str, p=Depends(principal)):
        service.source_revoke(p, org, source)
        return {"revoked": True}

    @app.post("/api/ingest", status_code=202)
    def ingest(request: Request, body: list[dict]):
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise Problem(401, "ingestion credential required")
        return service.ingest(header[7:], body)

    def filters_from(request):
        allowed = {"start", "end", "action", "host", "user", "source_ip", "severity", "source_id", "offset", "limit"}
        if set(request.query_params)-allowed:
            raise Problem(422, "unsupported search filter")
        filters = {k: v for k, v in request.query_params.items() if k not in ("offset", "limit") and v}
        for key in ("start", "end"):
            if key in filters:
                filters[key] = parse_time(filters[key]).isoformat()
        if "start" in filters and "end" in filters and filters["start"] > filters["end"]:
            raise Problem(422, "start must precede end")
        return filters

    @app.get("/api/orgs/{org}/events")
    def events(request: Request, org: str, offset: int = Query(0, ge=0, le=9950), limit: int = Query(50, ge=1, le=100), p=Depends(principal)):
        return service.event_search(p, org, filters_from(request), offset, limit)

    @app.get("/api/orgs/{org}/events/export")
    def export(request: Request, org: str, p=Depends(principal)):
        result = service.event_search(p, org, filters_from(request), 0, 100)
        with service.db.transaction() as tx:
            authorize(tx, p, org)
            audit(tx, org, p.user_id, "events.export", org, {"count": len(result["items"]), "limit": 100})
        return Response("\n".join(dump(e) for e in result["items"]), media_type="application/x-ndjson", headers={"Content-Disposition": 'attachment; filename="security-events.ndjson"'})

    @app.get("/api/orgs/{org}/events/{event_id}")
    def event(org: str, event_id: str, raw: bool = False, p=Depends(principal)):
        return service.event_get(p, org, event_id, raw)

    @app.get("/api/orgs/{org}/alerts")
    def alerts(org: str, p=Depends(principal)):
        return service.alert_list(p, org)

    @app.get("/api/orgs/{org}/alerts/{alert_id}")
    def alert(org: str, alert_id: str, p=Depends(principal)):
        return service.alert_get(p, org, alert_id)

    @app.patch("/api/orgs/{org}/alerts/{alert_id}")
    def triage(org: str, alert_id: str, body: TriageInput, p=Depends(principal)):
        service.alert_triage(p, org, alert_id, body.status, body.assigned_to)
        return {"updated": True}

    @app.get("/api/orgs/{org}/incidents")
    def incidents(org: str, p=Depends(principal)):
        return service.incident_list(p, org)

    @app.post("/api/orgs/{org}/incidents", status_code=201)
    def incident_create(org: str, body: IncidentInput, p=Depends(principal)):
        return service.incident_create(p, org, **body.model_dump())

    @app.get("/api/orgs/{org}/incidents/{incident_id}")
    def incident(org: str, incident_id: str, p=Depends(principal)):
        return service.incident_get(p, org, incident_id)

    @app.patch("/api/orgs/{org}/incidents/{incident_id}")
    def incident_update(org: str, incident_id: str, body: IncidentUpdate, p=Depends(principal)):
        service.incident_update(p, org, incident_id, **body.model_dump())
        return {"updated": True}

    @app.post("/api/orgs/{org}/incidents/{incident_id}/entries", status_code=201)
    def entry(org: str, incident_id: str, body: EntryInput, p=Depends(principal)):
        return service.incident_entry(p, org, incident_id, body.kind, body.body)

    @app.get("/api/orgs/{org}/incidents/{incident_id}/report")
    def report(org: str, incident_id: str, p=Depends(principal)):
        item = service.incident_get(p, org, incident_id)
        with service.db.transaction() as tx:
            authorize(tx, p, org)
            audit(tx, org, p.user_id, "incident.report", incident_id)
        return {k: item[k] for k in ("id", "title", "severity", "status", "resolution", "customer_summary", "created_at")}

    @app.get("/api/orgs/{org}/rules")
    def rules(org: str, p=Depends(principal)):
        return service.rule_list(p, org)

    @app.put("/api/orgs/{org}/rules/{rule_id}")
    def rule_update(org: str, rule_id: str, body: RuleInput, p=Depends(principal)):
        service.rule_update(p, org, rule_id, **body.model_dump())
        return {"updated": True}

    @app.post("/api/orgs/{org}/rules/{rule_id}/test")
    def rule_test(org: str, rule_id: str, body: RuleTestInput, p=Depends(principal)):
        if rule_id not in BY_ID:
            raise Problem(404, "rule not found")
        with service.db.transaction() as tx:
            authorize(tx, p, org, "analyst")
            history = []
            for event_id in set(body.event_ids):
                row = tx.one("SELECT document FROM events WHERE org_id=? AND id=?", (org, event_id))
                if not row:
                    raise Problem(404, "event not found")
                event = json.loads(row["document"])
                event["historical"] = False  # Explicit historical replay, without creating live alerts.
                history.append(event)
            results = [{"event_id": e["id"], "evidence": evidence_for(BY_ID[rule_id], e, history)} for e in history]
            audit(tx, org, p.user_id, "rule.test", rule_id, {"count": len(history)})
            return {"mode": "historical_dry_run", "rule_version": BY_ID[rule_id].version, "results": results}

    @app.get("/api/orgs/{org}/overview")
    def overview(org: str, p=Depends(principal)):
        return service.overview(p, org)

    @app.get("/api/orgs/{org}/assets")
    def assets(org: str, p=Depends(principal)):
        with service.db.transaction() as tx:
            authorize(tx, p, org)
            return {"hosts": tx.all("SELECT hostname AS name,COUNT(*) AS events,MAX(source_time) AS last_seen FROM events WHERE org_id=? AND hostname IS NOT NULL GROUP BY hostname ORDER BY events DESC LIMIT 200", (org,)),
                    "identities": tx.all("SELECT username AS name,COUNT(*) AS events,MAX(source_time) AS last_seen FROM events WHERE org_id=? AND username IS NOT NULL GROUP BY username ORDER BY events DESC LIMIT 200", (org,))}

    @app.get("/api/orgs/{org}/audit")
    def audit_log(org: str, p=Depends(principal)):
        return service.audit_list(p, org)

    @app.get("/api/orgs/{org}/dead-letters")
    def dead_letters(org: str, p=Depends(principal)):
        return service.dead_letters(p, org)

    @app.post("/api/orgs/{org}/dead-letters/{job}/retry")
    def retry(org: str, job: str, p=Depends(principal)):
        service.retry_dead(p, org, job)
        return {"queued": True}

    return app
