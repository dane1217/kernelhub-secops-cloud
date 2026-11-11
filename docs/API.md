# API contracts

The generated OpenAPI schema is `/api/openapi.json`; `/api/docs` describes request bodies. All browser calls use same-origin session cookies. Machine calls use `Authorization: Bearer kh_api_…`. Ingestion accepts **only** source credentials (`kh_ing_…`). Never put credentials in URLs.

## Authorization

Organization path parameters identify the requested scope, not an authorization grant. Every handler or business service validates current membership and credential scope. A platform administrator cannot use its global flag to bypass membership checks.

| API | Minimum access |
|---|---|
| GET `/api/me`, `/api/orgs` | Authenticated user |
| POST `/api/orgs` | Platform administrator using interactive session |
| GET `/api/orgs/{org}/overview`, `/workspaces`, `/members`, `/assets` | Viewer |
| GET `/sources`, `/alerts`, `/incidents`, `/rules`, `/audit` | Viewer |
| POST `/sources`; POST `/sources/{source}/revoke` | Organization administrator |
| POST `/invitations`; DELETE `/members/{user}` | Organization administrator |
| POST `/credentials`; POST `/credentials/revoke` | Organization administrator |
| POST `/api/invitations/accept` | Interactive identity with matching verified email |
| GET `/events`, `/events/{id}`, `/events/export` | Viewer; reads/exports are tenant scoped |
| PATCH `/alerts/{id}` | Analyst; assignee must be an analyst/admin member |
| POST `/incidents`; PATCH `/incidents/{id}`; POST `/incidents/{id}/entries` | Analyst |
| GET `/incidents/{id}/report` | Viewer; limited customer-summary fields |
| PUT `/rules/{id}` | Organization administrator |
| POST `/rules/{id}/test` | Analyst; historical dry run over up to 1,000 tenant event IDs |
| GET `/dead-letters`; POST `/dead-letters/{job}/retry` | Organization administrator |
| POST `/api/ingest` | Unexpired source ingestion credential |

All abbreviated paths in the table are beneath `/api/orgs/{org}`. Interactive mutations require exact `Origin=PUBLIC_URL` and the `X-CSRF-Token` returned by `/api/me`. External OIDC bearer JWTs are not accepted as general API credentials.

## Event schema v1.0

Normalized collector input is an array:

```json
[{"event_id":"collector-stable-123","timestamp":"2026-11-11T12:00:00Z","action":"auth.failure","host":"server01","user":"alice","source_ip":"192.0.2.10","outcome":"failure","severity":"medium","synthetic":true}]
```

`timestamp` and `action` are required. Optional: `event_id`, `host`, `user`, source/destination IP, outcome, severity, `command_line`, `synthetic`. Actions are a bounded enum defined in `events.py`. Windows/Linux sources use the documented input adapters. Unknown auxiliary fields are kept only in the redacted original; they cannot alter reserved normalized fields. Supplying tenant/workspace identifiers is rejected.

The stored/searchable document adds server-owned `id`, `tenant_id`, `workspace_id`, `source_id`, `source_time`, `received_at`, `category`, `schema_version`, `parser_version`, `raw_ref`, `data_mode` and `historical`. `raw_ref` is a reference, never a public download URL. `data_mode=synthetic` is preserved for demo events; older-than-24-hour telemetry is marked historical.

An omitted external ID is a SHA-256 hash of canonical original JSON. A reused external ID returns the original record even if the body differs: collectors must use a stable unique record identity and must not reuse it for revisions.

```json
{"accepted":5,"duplicates":0,"event_ids":["server-generated-uuid"],"state":"persisted_pending_index"}
```

The abbreviated ID list above illustrates shape; the actual list has one ID per delivered item, including duplicates.

## Bounded search and export

GET `/events?start=…&end=…&action=auth.failure&user=alice&offset=0&limit=50` returns `{items,total}`. Allowed exact-match fields: action, host, user, source_ip, severity, source_id. Time filters use source time and require an explicit timezone. Pagination is stable source time descending / event ID ascending, at most 100 items and offsets through 9,950. New ingestion can shift offset pagination; a snapshot cursor is deferred.

Unrestricted OpenSearch DSL, regex, scripts, aggregations and arbitrary index names are rejected. Empty tenant indexes return no matches. Search-service errors return 503; no SQL fallback silently changes search behavior. Export produces up to 100 matching NDJSON records, never arbitrary cross-tenant exports. Large asynchronous exports are deferred.

## Incident lifecycle

`new → triaging → investigating → contained → resolved → closed`, with `investigating → resolved` permitted when containment is unnecessary. A contained/resolved incident may return to investigating. Closed incidents are immutable in lifecycle; notes can still be appended. Resolution requires true_positive, false_positive, benign_activity or insufficient_evidence. Every transition records actor, old/new status, resolution and summary in the append-only audit trail.

Entries support note/task/evidence/feedback as attributed text. Tasks currently do not have separate completion state. Evidence entries are analyst notes, not binary uploads or cryptographic chain-of-custody records. Alert evidence retains source event IDs, source time, parser version, original reference and rule/tuning snapshot.

## Errors and limits

401 invalid credentials/session; 403 missing membership/role/CSRF; 404 absent object in the authorized tenant; 409 invalid lifecycle/last-administrator change; 413 body limit; 415 compression unsupported; 422 invalid input; 429 rate/quota; 503 unavailable dependency/backpressure. Validation responses omit supplied values. Retry 429/503 with exponential backoff and jitter; preserve external IDs.

`/internal/metrics` and `/internal/health/ready` are private-network endpoints; the edge blocks them. `/api/health/live` only confirms the process is alive. Interactive API documentation contains contracts but no customer data or credentials.
