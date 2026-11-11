"""All tenant authorization and business workflows live here, not in the browser."""
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import hmac
import json
import secrets
import uuid

from .events import InvalidEvent, normalize, now, parse_time, redact
from .rules import BY_ID, RULES, correlation_key, evidence_for


def uid():
    return str(uuid.uuid4())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def dump(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


class Problem(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


@dataclass(frozen=True)
class Principal:
    user_id: str
    platform_admin: bool = False
    scoped_org: str | None = None
    scoped_role: str | None = None


ROLES = {"viewer": 0, "analyst": 1, "org_admin": 2}
TRANSITIONS = {"new": {"triaging"}, "triaging": {"investigating"},
               "investigating": {"contained", "resolved"}, "contained": {"investigating", "resolved"},
               "resolved": {"investigating", "closed"}, "closed": set()}


def audit(tx, org, actor, action, target, detail=None):
    tx.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?)", (uid(), org, actor, action, target, dump(redact(detail or {})), now()))


def authorize(tx, principal, org, minimum="viewer"):
    # Platform administration does not silently grant access to customer telemetry.
    if principal.scoped_org is not None and principal.scoped_org != org:
        raise Problem(403, "organization access denied")
    membership = tx.one("SELECT role FROM memberships WHERE org_id=? AND user_id=?", (org, principal.user_id))
    if not membership:
        raise Problem(403, "organization access denied")
    effective = membership["role"]
    if principal.scoped_role:
        effective = min((effective, principal.scoped_role), key=lambda r: ROLES[r])
    if ROLES[effective] < ROLES[minimum]:
        raise Problem(403, "insufficient role")
    return effective


def member_target(tx, org, user_id):
    if user_id and not tx.one("SELECT role FROM memberships WHERE org_id=? AND user_id=? AND role!='viewer'", (org, user_id)):
        raise Problem(422, "assignee must be an analyst or administrator in this organization")


class Service:
    def __init__(self, db, search, objects):
        self.db, self.search, self.objects = db, search, objects

    def register_identity(self, subject, email, bootstrap_subject=""):
        with self.db.transaction() as tx:
            row = tx.one("SELECT * FROM users WHERE subject=?", (subject,))
            if not row:
                row = {"id": uid(), "subject": subject, "email": email.lower(),
                       "platform_admin": int(bool(bootstrap_subject) and subject == bootstrap_subject)}
                tx.execute("INSERT INTO users VALUES (?,?,?,?)", tuple(row.values()))
                audit(tx, None, row["id"], "identity.register", row["id"])
            else:
                tx.execute("UPDATE users SET email=? WHERE id=?", (email.lower(), row["id"]))
            return Principal(row["id"], bool(row["platform_admin"]))

    def organization_create(self, principal, name):
        if not principal.platform_admin or principal.scoped_org:
            raise Problem(403, "platform administrator required")
        org, workspace = uid(), uid()
        with self.db.transaction() as tx:
            tx.execute("INSERT INTO organizations(id,name,created_at) VALUES (?,?,?)", (org, name, now()))
            tx.execute("INSERT INTO workspaces VALUES (?,?,?)", (workspace, org, "Default"))
            tx.execute("INSERT INTO memberships VALUES (?,?,?)", (org, principal.user_id, "org_admin"))
            audit(tx, org, principal.user_id, "organization.create", org, {"name": name})
        return {"id": org, "name": name, "workspace_id": workspace}

    def organizations(self, principal):
        with self.db.transaction() as tx:
            result = tx.all("SELECT o.*,m.role FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE m.user_id=? ORDER BY o.name", (principal.user_id,))
            return [x for x in result if principal.scoped_org is None or x["id"] == principal.scoped_org]

    def workspaces(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT * FROM workspaces WHERE org_id=? ORDER BY name", (org,))

    def source_create(self, principal, org, workspace, name, kind):
        source_id, key = uid(), "kh_ing_" + secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            if kind not in ("normalized", "windows", "linux") or not tx.one("SELECT id FROM workspaces WHERE org_id=? AND id=?", (org, workspace)):
                raise Problem(422, "invalid workspace or parser")
            tx.execute("INSERT INTO sources(id,org_id,workspace_id,name,kind) VALUES (?,?,?,?,?)", (source_id, org, workspace, name, kind))
            tx.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?)", (digest(key), org, source_id, "ingest", "ingest", None, (parse_time(now())+timedelta(days=90)).isoformat(), 0))
            audit(tx, org, principal.user_id, "source.create", source_id, {"kind": kind, "workspace": workspace})
        return {"id": source_id, "credential": key, "expires_in_days": 90}

    def sources(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT * FROM sources WHERE org_id=? ORDER BY name", (org,))

    def source_revoke(self, principal, org, source):
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            if not tx.one("SELECT id FROM sources WHERE org_id=? AND id=?", (org, source)):
                raise Problem(404, "source not found")
            tx.execute("UPDATE sources SET revoked=1 WHERE org_id=? AND id=?", (org, source))
            tx.execute("UPDATE credentials SET revoked=1 WHERE org_id=? AND source_id=?", (org, source))
            audit(tx, org, principal.user_id, "source.revoke", source)

    def invite(self, principal, org, email, role):
        if role not in ROLES:
            raise Problem(422, "invalid role")
        token = secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            tx.execute("INSERT INTO invitations VALUES (?,?,?,?,?,NULL)", (digest(token), org, email.lower(), role, (parse_time(now())+timedelta(days=2)).isoformat()))
            audit(tx, org, principal.user_id, "membership.invite", email.lower(), {"role": role})
        return {"invitation": token, "expires_in_hours": 48}

    def accept_invite(self, principal, token):
        with self.db.transaction() as tx:
            # A scoped API credential cannot accept an invitation to broaden access.
            if principal.scoped_org:
                raise Problem(403, "interactive login required")
            lock = " FOR UPDATE" if tx.postgres else ""
            invitation = tx.one("SELECT * FROM invitations WHERE token_hash=?"+lock, (digest(token),))
            user = tx.one("SELECT email FROM users WHERE id=?", (principal.user_id,))
            if not invitation or invitation["consumed_at"] or invitation["expires_at"] <= now() or not hmac.compare_digest(invitation["email"], user["email"]):
                raise Problem(403, "invalid or expired invitation")
            tx.lock_org(invitation["org_id"])
            existing = tx.one("SELECT role FROM memberships WHERE org_id=? AND user_id=?", (invitation["org_id"], principal.user_id))
            if existing and existing["role"] == "org_admin" and invitation["role"] != "org_admin":
                admins = tx.one("SELECT COUNT(*) AS n FROM memberships WHERE org_id=? AND role='org_admin'", (invitation["org_id"],))
                if admins["n"] <= 1:
                    raise Problem(409, "cannot downgrade the last administrator")
            tx.execute("INSERT INTO memberships VALUES (?,?,?) ON CONFLICT(org_id,user_id) DO UPDATE SET role=excluded.role", (invitation["org_id"], principal.user_id, invitation["role"]))
            tx.execute("UPDATE invitations SET consumed_at=? WHERE token_hash=?", (now(), digest(token)))
            audit(tx, invitation["org_id"], principal.user_id, "membership.accept", principal.user_id, {"role": invitation["role"]})
            return {"org_id": invitation["org_id"]}

    def members(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT u.id,u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=? ORDER BY u.email", (org,))

    def remove_member(self, principal, org, user_id):
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            tx.lock_org(org)
            admins = tx.all("SELECT user_id FROM memberships WHERE org_id=? AND role='org_admin'", (org,))
            if len(admins) == 1 and admins[0]["user_id"] == user_id:
                raise Problem(409, "cannot remove the last administrator")
            tx.execute("DELETE FROM memberships WHERE org_id=? AND user_id=?", (org, user_id))
            tx.execute("UPDATE credentials SET revoked=1 WHERE org_id=? AND user_id=?", (org, user_id))
            audit(tx, org, principal.user_id, "membership.remove", user_id)

    def api_credential(self, principal, org, role):
        if role not in ROLES:
            raise Problem(422, "invalid role")
        token = "kh_api_" + secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            effective = authorize(tx, principal, org, "org_admin")
            if ROLES[role] > ROLES[effective]:
                raise Problem(403, "cannot elevate credential")
            tx.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?)", (digest(token), org, None, "api", role, principal.user_id, (parse_time(now())+timedelta(days=7)).isoformat(), 0))
            audit(tx, org, principal.user_id, "credential.create", "api", {"role": role})
        return {"credential": token, "expires_in_days": 7}

    def authenticate_api(self, token):
        with self.db.transaction() as tx:
            row = tx.one("SELECT * FROM credentials WHERE token_hash=? AND purpose='api' AND revoked=0", (digest(token),))
            if not row or row["expires_at"] <= now():
                raise Problem(401, "invalid credential")
            p = Principal(row["user_id"], False, row["org_id"], row["role"])
            authorize(tx, p, row["org_id"])
            return p

    def ingest(self, key, batch):
        received = now()
        if not isinstance(batch, list) or not 1 <= len(batch) <= 100:
            raise Problem(422, "send an array of 1 to 100 events")
        parser_failure = None
        with self.db.transaction() as tx:
            credential = tx.one("SELECT c.*,s.kind,s.workspace_id,s.revoked AS source_revoked FROM credentials c JOIN sources s ON s.id=c.source_id AND s.org_id=c.org_id WHERE c.token_hash=? AND c.purpose='ingest' AND c.revoked=0", (digest(key),))
            if not credential or credential["source_revoked"] or credential["expires_at"] <= received:
                raise Problem(401, "invalid ingestion credential")
            org, source = credential["org_id"], credential["source_id"]
            tx.lock_org(org)
            limits = tx.one("SELECT * FROM organizations WHERE id=?", (org,))
            # Limit attempts too; duplicates consume rate budget but not daily stored-event quota.
            minute = "minute:" + received[:16]
            count = tx.one("SELECT count FROM usage_counters WHERE org_id=? AND bucket=?", (org, minute))
            if count and count["count"] + len(batch) > limits["rate_minute"]:
                raise Problem(429, "ingestion rate limit exceeded")
            if len(batch) > limits["rate_minute"]:
                raise Problem(429, "ingestion rate limit exceeded")
            try:
                normalized = [normalize(e, credential["kind"], received) for e in batch]
            except InvalidEvent as exc:
                parser_failure = str(exc)
                tx.execute("UPDATE sources SET parser_failures=parser_failures+1 WHERE org_id=? AND id=?", (org, source))
                audit(tx, org, source, "ingestion.parse_failure", source, {"reason": parser_failure})
                normalized = []
            tx.execute("INSERT INTO usage_counters VALUES (?,?,?) ON CONFLICT(org_id,bucket) DO UPDATE SET count=usage_counters.count+excluded.count", (org, minute, len(batch)))
            ids, duplicates = [], 0
            for raw, event in zip(batch, normalized):
                existing = tx.one("SELECT id FROM events WHERE org_id=? AND source_id=? AND external_id=?", (org, source, event["external_id"]))
                if existing:
                    ids.append(existing["id"])
                    duplicates += 1
                    continue
                day = "day:" + received[:10]
                daily = tx.one("SELECT count FROM usage_counters WHERE org_id=? AND bucket=?", (org, day))
                if daily and daily["count"] >= limits["quota_daily"]:
                    raise Problem(429, "daily ingestion quota exceeded")
                pending = tx.one("SELECT COUNT(*) AS n FROM outbox WHERE org_id=? AND status='pending'", (org,))["n"]
                if pending >= 10000:
                    raise Problem(503, "ingestion backlog full; retry later")
                event_id = uid()
                raw_key = f"{org}/{credential['workspace_id']}/{source}/{event_id}.json"
                event.update(id=event_id, tenant_id=org, workspace_id=credential["workspace_id"], source_id=source, raw_ref=raw_key)
                tx.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    event_id, org, source, credential["workspace_id"], event["external_id"], event["source_time"], received,
                    event["action"], event["category"], event["host"], event["user"], event["source_ip"], event["destination_ip"],
                    event["outcome"], event["severity"], dump(event), dump(redact(raw)), raw_key, 0))
                tx.execute("INSERT INTO outbox(id,org_id,event_id,next_attempt) VALUES (?,?,?,?)", (uid(), org, event_id, received))
                tx.execute("INSERT INTO usage_counters VALUES (?,?,1) ON CONFLICT(org_id,bucket) DO UPDATE SET count=usage_counters.count+1", (org, day))
                ids.append(event_id)
            if normalized:
                tx.execute("UPDATE sources SET last_seen=? WHERE org_id=? AND id=?", (received, org, source))
                audit(tx, org, source, "ingestion.accept", source, {"received": len(batch), "duplicates": duplicates})
        if parser_failure:
            raise Problem(422, parser_failure)
        return {"accepted": len(ids)-duplicates, "duplicates": duplicates, "event_ids": ids, "state": "persisted_pending_index"}

    def process_one(self):
        """At-least-once delivery with transaction locks and stable external side-effect IDs."""
        with self.db.transaction() as tx:
            jobs = tx.all("SELECT id,org_id FROM outbox WHERE status='pending' AND next_attempt<=? ORDER BY next_attempt LIMIT 50", (now(),))
        for candidate in jobs:
            with self.db.transaction() as tx:
                # Organization lock FIRST on every worker path; avoids cross-job deadlocks.
                if tx.postgres:
                    locked = tx.one("SELECT id FROM organizations WHERE id=? FOR UPDATE SKIP LOCKED", (candidate["org_id"],))
                    if not locked:
                        continue
                else:
                    tx.lock_org(candidate["org_id"])
                job = tx.one("SELECT * FROM outbox WHERE id=? AND status='pending' AND next_attempt<=?", (candidate["id"], now()))
                if not job:
                    continue
                row = tx.one("SELECT * FROM events WHERE id=? AND org_id=?", (job["event_id"], job["org_id"]))
                if not row:
                    raise RuntimeError("outbox provenance violation")
                event = json.loads(row["document"])
                try:
                    self.objects.put(job["org_id"], row["raw_key"], row["raw_json"].encode())
                    self.search.index(job["org_id"], event)
                except Exception:
                    # Do not persist exception text: URLs/headers can include credentials.
                    attempts = job["attempts"]+1
                    status = "dead" if attempts >= 8 else "pending"
                    due = (parse_time(now())+timedelta(seconds=min(300, 2**attempts))).isoformat()
                    tx.execute("UPDATE outbox SET attempts=?,status=?,next_attempt=?,last_error=? WHERE id=? AND org_id=?", (attempts, status, due, "archive_or_search_unavailable", job["id"], job["org_id"]))
                    audit(tx, job["org_id"], "worker", "pipeline."+status, job["event_id"], {"attempt": attempts})
                    return True
                self._detect(tx, event)
                tx.execute("UPDATE events SET indexed=1 WHERE org_id=? AND id=?", (job["org_id"], event["id"]))
                tx.execute("UPDATE outbox SET status='done',last_error=NULL WHERE id=? AND org_id=?", (job["id"], job["org_id"]))
                tx.execute("INSERT INTO worker_health VALUES ('pipeline',?) ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen", (now(),))
                return True
        return False

    def _detect(self, tx, event):
        if event.get("historical"):
            return
        org = event["tenant_id"]
        start = (parse_time(event["source_time"])-timedelta(minutes=5)).isoformat()
        end = (parse_time(event["source_time"])+timedelta(minutes=5)).isoformat()
        history = [json.loads(r["document"]) for r in tx.all("SELECT document FROM events WHERE org_id=? AND source_time>=? AND source_time<=? ORDER BY source_time,id LIMIT 10001", (org, start, end))]
        # Fail visibly rather than silently evaluating a truncated correlation window.
        if len(history) > 10000:
            audit(tx, org, "worker", "detection.window_overflow", event["id"])
            return
        for rule in RULES:
            setting = tx.one("SELECT * FROM rule_settings WHERE org_id=? AND rule_id=?", (org, rule.id))
            if setting and (not setting["enabled"] or setting["suppressed_until"] and setting["suppressed_until"] > event["received_at"]):
                continue
            exclusions = json.loads(setting["excluded_users"]) if setting else []
            eligible = [h for h in history if h.get("user") not in exclusions]
            # Late failures re-evaluate already-arrived successes in the same source-time window.
            candidates = [event]
            if event["action"] == "auth.failure" and rule.id == "KH-002":
                candidates = [h for h in eligible if h["action"] == "auth.success"]
            for candidate in candidates:
                if candidate.get("user") in exclusions:
                    continue
                evidence = evidence_for(rule, candidate, eligible, setting["threshold_count"] if setting else None)
                if not evidence:
                    continue
                group = correlation_key(rule, candidate)
                bucket = int(parse_time(candidate["source_time"]).timestamp()) // 600
                effective = {"threshold_count": setting["threshold_count"] if setting else None, "excluded_users": exclusions}
                fingerprint = digest(dump([rule.id, rule.version, effective, group, bucket]))
                existing = tx.one("SELECT id,evidence_ids FROM alerts WHERE org_id=? AND fingerprint=?", (org, fingerprint))
                if existing:
                    merged = sorted(set(json.loads(existing["evidence_ids"])+evidence))
                    tx.execute("UPDATE alerts SET evidence_ids=? WHERE org_id=? AND id=?", (dump(merged), org, existing["id"]))
                    if merged != sorted(json.loads(existing["evidence_ids"])):
                        audit(tx, org, "worker", "alert.evidence_append", existing["id"], {"evidence": evidence})
                else:
                    alert_id = uid()
                    tx.execute("INSERT INTO alerts(id,org_id,rule_id,rule_version,rule_snapshot,title,severity,fingerprint,created_at,evidence_ids) VALUES (?,?,?,?,?,?,?,?,?,?)", (alert_id, org, rule.id, rule.version, dump({**rule.document(), "effective_settings": effective}), rule.title, rule.severity, fingerprint, now(), dump(evidence)))
                    audit(tx, org, "worker", "alert.create", alert_id, {"rule": rule.id, "version": rule.version, "evidence": evidence})

    def retry_dead(self, principal, org, job):
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            result = tx.execute("UPDATE outbox SET status='pending',attempts=0,next_attempt=?,last_error=NULL WHERE org_id=? AND id=? AND status='dead'", (now(), org, job))
            if result.rowcount != 1:
                raise Problem(404, "dead-letter job not found")
            audit(tx, org, principal.user_id, "pipeline.replay", job)

    def event_search(self, principal, org, filters, offset=0, limit=50):
        if offset < 0 or offset > 9950 or not 1 <= limit <= 100:
            raise Problem(422, "invalid pagination")
        allowed = {"action", "host", "user", "source_ip", "severity", "source_id", "start", "end"}
        if set(filters)-allowed:
            raise Problem(422, "unsupported filter")
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            try:
                result = self.search.search(org, filters, offset, limit)
            except Exception as exc:
                raise Problem(503, "event search unavailable; ingestion remains durable") from exc
            # Defense in depth against a broken/misconfigured search adapter.
            if any(e.get("tenant_id") != org for e in result["items"]):
                raise Problem(503, "search isolation check failed")
            return result

    def event_get(self, principal, org, event_id, raw=False):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            row = tx.one("SELECT document,raw_json FROM events WHERE org_id=? AND id=?", (org, event_id))
            if not row:
                raise Problem(404, "event not found")
            audit(tx, org, principal.user_id, "evidence.read", event_id, {"raw": raw})
            return json.loads(row["raw_json"] if raw else row["document"])

    def alert_list(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT * FROM alerts WHERE org_id=? ORDER BY created_at DESC LIMIT 200", (org,))

    def alert_get(self, principal, org, alert_id):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            alert = tx.one("SELECT * FROM alerts WHERE org_id=? AND id=?", (org, alert_id))
            if not alert:
                raise Problem(404, "alert not found")
            alert["rule"] = json.loads(alert.pop("rule_snapshot"))
            alert["evidence"] = []
            for event_id in json.loads(alert["evidence_ids"]):
                event = tx.one("SELECT document FROM events WHERE org_id=? AND id=?", (org, event_id))
                if event:
                    alert["evidence"].append(json.loads(event["document"]))
            audit(tx, org, principal.user_id, "alert.read", alert_id)
            return alert

    def alert_triage(self, principal, org, alert_id, status, assigned_to=None):
        if status not in ("new", "triaging", "escalated", "dismissed"):
            raise Problem(422, "invalid alert status")
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "analyst")
            member_target(tx, org, assigned_to)
            if not tx.one("SELECT id FROM alerts WHERE org_id=? AND id=?", (org, alert_id)):
                raise Problem(404, "alert not found")
            tx.execute("UPDATE alerts SET status=?,assigned_to=? WHERE org_id=? AND id=?", (status, assigned_to, org, alert_id))
            audit(tx, org, principal.user_id, "alert.triage", alert_id, {"status": status, "assigned_to": assigned_to})

    def incident_create(self, principal, org, title, severity, alerts, assigned_to=None):
        if severity not in ("low", "medium", "high", "critical") or not alerts or len(alerts) > 100:
            raise Problem(422, "incident requires severity and 1 to 100 alerts")
        incident_id = uid()
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "analyst")
            member_target(tx, org, assigned_to)
            for alert in set(alerts):
                if not tx.one("SELECT id FROM alerts WHERE org_id=? AND id=?", (org, alert)):
                    raise Problem(404, "alert not found")
            tx.execute("INSERT INTO incidents(id,org_id,title,severity,assigned_to,created_at) VALUES (?,?,?,?,?,?)", (incident_id, org, title, severity, assigned_to, now()))
            for alert in set(alerts):
                tx.execute("INSERT INTO incident_alerts VALUES (?,?,?)", (org, incident_id, alert))
            audit(tx, org, principal.user_id, "incident.create", incident_id, {"alerts": alerts, "severity": severity, "title": title})
        return {"id": incident_id}

    def incident_list(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT * FROM incidents WHERE org_id=? ORDER BY created_at DESC LIMIT 200", (org,))

    def incident_get(self, principal, org, incident_id):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            item = tx.one("SELECT * FROM incidents WHERE org_id=? AND id=?", (org, incident_id))
            if not item:
                raise Problem(404, "incident not found")
            item["entries"] = tx.all("SELECT * FROM incident_entries WHERE org_id=? AND incident_id=? ORDER BY created_at,id", (org, incident_id))
            item["alerts"] = tx.all("SELECT alert_id FROM incident_alerts WHERE org_id=? AND incident_id=?", (org, incident_id))
            item["timeline"] = tx.all("SELECT * FROM audit WHERE org_id=? AND target=? ORDER BY created_at,id", (org, incident_id))
            return item

    def incident_update(self, principal, org, incident_id, status, resolution=None, summary=""):
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "analyst")
            tx.lock_org(org)
            incident = tx.one("SELECT * FROM incidents WHERE org_id=? AND id=?", (org, incident_id))
            if not incident:
                raise Problem(404, "incident not found")
            if status not in TRANSITIONS[incident["status"]]:
                raise Problem(409, "invalid incident transition")
            if status in ("resolved", "closed") and resolution not in ("true_positive", "false_positive", "benign_activity", "insufficient_evidence"):
                raise Problem(422, "resolution category required")
            tx.execute("UPDATE incidents SET status=?,resolution=?,customer_summary=? WHERE org_id=? AND id=?", (status, resolution, summary, org, incident_id))
            audit(tx, org, principal.user_id, "incident.transition", incident_id, {"from": incident["status"], "to": status, "resolution": resolution, "summary": summary})

    def incident_entry(self, principal, org, incident_id, kind, body):
        if kind not in ("note", "task", "evidence", "feedback") or not 1 <= len(body) <= 8000:
            raise Problem(422, "invalid entry")
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "analyst")
            if not tx.one("SELECT id FROM incidents WHERE org_id=? AND id=?", (org, incident_id)):
                raise Problem(404, "incident not found")
            entry = uid()
            tx.execute("INSERT INTO incident_entries VALUES (?,?,?,?,?,?,?)", (entry, org, incident_id, kind, redact(body), principal.user_id, now()))
            audit(tx, org, principal.user_id, "incident."+kind, incident_id, {"entry_id": entry})
            return {"id": entry}

    def rule_update(self, principal, org, rule_id, enabled, excluded_users, suppressed_until=None, threshold_count=None):
        if rule_id not in BY_ID or len(excluded_users) > 100:
            raise Problem(422, "invalid rule")
        if suppressed_until:
            suppressed_until = parse_time(suppressed_until).isoformat(timespec="microseconds")
        if threshold_count is not None and (rule_id not in ("KH-001", "KH-002", "KH-010") or not 2 <= threshold_count <= 100):
            raise Problem(422, "invalid threshold")
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            tx.execute("INSERT INTO rule_settings VALUES (?,?,?,?,?,?) ON CONFLICT(org_id,rule_id) DO UPDATE SET enabled=excluded.enabled,suppressed_until=excluded.suppressed_until,excluded_users=excluded.excluded_users,threshold_count=excluded.threshold_count", (org, rule_id, int(enabled), suppressed_until, dump(excluded_users), threshold_count))
            audit(tx, org, principal.user_id, "rule.update", rule_id, {"enabled": enabled, "excluded_users": excluded_users, "suppressed_until": suppressed_until, "threshold_count": threshold_count})

    def rule_list(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            settings = {r["rule_id"]: r for r in tx.all("SELECT * FROM rule_settings WHERE org_id=?", (org,))}
            return [{**r.document(), "settings": settings.get(r.id)} for r in RULES]

    def overview(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return {"events": tx.one("SELECT COUNT(*) AS total,MAX(received_at) AS last_received FROM events WHERE org_id=?", (org,)),
                    "incidents": tx.all("SELECT severity,COUNT(*) AS count FROM incidents WHERE org_id=? AND status NOT IN ('resolved','closed') GROUP BY severity", (org,)),
                    "alerts": tx.all("SELECT severity,COUNT(*) AS count FROM alerts WHERE org_id=? GROUP BY severity", (org,)),
                    "pipeline": tx.all("SELECT status,COUNT(*) AS count,MIN(next_attempt) AS oldest FROM outbox WHERE org_id=? GROUP BY status", (org,)),
                    "storage": tx.one("SELECT COALESCE(SUM(LENGTH(raw_json)+LENGTH(document)),0) AS database_payload_bytes FROM events WHERE org_id=?", (org,)),
                    "usage": tx.all("SELECT bucket,count FROM usage_counters WHERE org_id=? AND bucket LIKE 'day:%' ORDER BY bucket DESC LIMIT 7", (org,)),
                    "worker": tx.one("SELECT last_seen FROM worker_health WHERE name='scheduler'"),
                    "limits": tx.one("SELECT quota_daily,rate_minute,retention_days,ai_enabled FROM organizations WHERE id=?", (org,)),
                    "data_note": "Counts include synthetic events explicitly labeled in Event Search. Storage is DB payload bytes only."}

    def audit_list(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org)
            return tx.all("SELECT * FROM audit WHERE org_id=? ORDER BY created_at DESC LIMIT 500", (org,))

    def dead_letters(self, principal, org):
        with self.db.transaction() as tx:
            authorize(tx, principal, org, "org_admin")
            return tx.all("SELECT * FROM outbox WHERE org_id=? AND status='dead' ORDER BY next_attempt LIMIT 200", (org,))
