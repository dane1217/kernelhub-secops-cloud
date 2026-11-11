# Implementation status and backlog

## Implemented source

- Modular FastAPI backend, PostgreSQL migrations, durable event/outbox persistence and real OpenSearch/S3 adapters.
- OIDC/PKCE and opaque server sessions, CSRF, organization/workspace membership, four platform/product roles, explicit analyst invitations, source and API credentials.
- JSON ingestion, bounded normalization, Windows/Linux parser contracts, hash deduplication, quotas/rate/backlog limits, parser-failure visibility and dead-letter replay.
- Ten deterministic rules, tuning/excluded users/suppression, evidence and rule/tuning snapshots, alert triage/assignment and historical baseline-rule dry runs.
- Incidents, linked alerts/events, lifecycle validation, attributed notes/task/evidence/feedback text, customer summaries and authorized JSON reports.
- Tenant-safe bounded event search/NDJSON export, observed hosts/identities, usage/health queries and separate append-only audit.
- Next.js SOC console with organization selector, themes, empty/loading/error/permission states and real API calls. Deferred capabilities explicitly labeled unavailable.
- Local Compose, cloud VM Ansible/Compose reference, TLS edge, CI/dependency/container checks, synthetic fixtures, maintained-collector examples and backup/restore procedure.

**Implemented source is not the same as validated deployment. Phase 1 is still pending its full-stack acceptance gate.** See VALIDATION.md.

## Synthetic / test-only

- Demo sender and fixture files are explicitly synthetic and labeled in normalized/search data.
- In-memory search/object adapters exist only in tests; they cannot be selected by runtime environment settings.
- Browser fixture test mocks HTTP for UI behavior. It does not establish live identity or container behavior.
- SQLite exists only in hermetic domain/HTTP test setup, never as a cloud runtime alternative.

## Phase 1 validation still required

Dependency resolution, frontend typecheck/build, HTTP tests and an actual PostgreSQL/OpenSearch/S3 round trip have passed in CI. Still required: OIDC/OTP/invitation browser flow, worker kill/restart during processing, service-outage drill, collector host validation and reproducible cloud deployment/restore. Version constraints/npm locks are now checked in. CI defines automated subsets; report each check's observed result separately from the overall workflow outcome.

## Phase 2 — pilot readiness

Automated coordinated retention/deletion/legal holds; backup expiration and deletion ledger; tested restore drills; dependency locks/digests; byte/storage quotas; per-source missing-telemetry alerts and notifications; external immutable audit export; sanitized centralized error reporting; CSP nonces and accessibility validation; task completion/evidence uploads; credential rotation UX; large reports/exports; snapshot search cursors; rule-engine performance improvements; measured ingestion/search workloads and failure testing; service account/worker scope hardening and independent security review.

Explicit multi-customer membership and ingestion retries/last_seen are already in the source, but pilot readiness as a whole is not complete. Per-workspace authorization is deferred.

## Phase 3 — SOAR, not implemented

Versioned triggers/conditions/action interface; read-only allowlisted enrichment; execution history, deadlines, retries, cancellation and idempotency; dry runs; scoped/expiring action-specific approvals and reauthorization. Initial playbooks: suspicious-IP enrichment; compromised-account investigation with approval request; verified exposure-to-incident tasks. Disruptive actions remain unavailable; no remote shell feature will be added.

## Phase 4 — exposure and optional AI, not implemented

Domain ownership verification, authorized monitored identities, licensed intelligence API connectors, scheduled usage/rate accounting, match confidence/source coverage, deduplication and remediation incidents. No provider credentials or live findings are present. No synthetic findings are presented as live intelligence.

Optional tenant-controlled AI: minimized evidence with citations, observation/hypothesis separation, prompt-injection resistance, usage budgets and report drafting. No AI provider is configured or called. AI will never authorize response or receive unrestricted execution tools.

Sigma compatibility, regulatory certification and high availability are not claimed.
