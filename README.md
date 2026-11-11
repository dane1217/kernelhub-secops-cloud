# KernelHub SecOps Cloud

A multi-tenant security monitoring application built as a modular monolith with background workers. Product branding is configured with `PRODUCT_NAME`.

**Status: Phase 1 implementation, pending full-stack validation. Not production approved.** The repository contains real backend workflows and a Next.js console. Later-phase automation, exposure intelligence, and AI are explicitly unavailable. No customer production servers are used.

## Start locally

Prerequisites: Docker Desktop with its Linux engine running, Docker Compose, and Python 3.12+. Allow approximately 8 GB of Docker memory for development; this is a configuration allowance, not a measured capacity claim.

```bash
python scripts/setup.py
docker compose config --quiet
docker compose up --build -d --wait
```

Open <http://localhost:8080>. Read `.local/pilot-login.txt` privately for the randomly generated development login. Enroll a TOTP authenticator during the first sign-in. No default password is checked into Git.

1. In **Platform Administration**, create an organization.
2. In **Integrations**, create a **Normalized JSON v1** source. Copy its one-time credential.
3. Run `python scripts/send_demo.py` and paste the credential into its hidden prompt. It sends six explicitly synthetic events using current timestamps.
4. Wait for the worker, then search `auth.failure` in **Event Search**. Open **Alerts** to inspect KH-001 and KH-002 with rule snapshots and evidence.
5. Create an incident from an alert. Move it through triage and investigation to resolution, adding an explanation and resolution category.
6. Review the audit trail under **Organization Settings**. Create a second organization and use invitations to test independently scoped access.

Static files in `fixtures/` retain fixed timestamps: after 24 hours they are historical and do not generate live alerts. The demo sender always uses current times. Production dashboards are never pre-populated.

## Architecture

- **Next.js / TypeScript**: responsive console, opaque session cookie, no integration secrets or direct search-engine access.
- **FastAPI / Python**: authentication, authorization, ingestion, detections, incidents, reports, audit, bounded search contracts.
- **PostgreSQL**: authoritative application state, normalized/redacted events, ingestion outbox, immutable audit records.
- **Celery / Redis**: scheduled draining of the durable SQL outbox. Redis uses AOF; SQL remains the source of truth when the broker is lost.
- **OpenSearch**: separate index per organization plus an enforced tenant filter. Search accepts only explicit field/time filters.
- **S3-compatible storage**: redacted event archives under organization/workspace/source/event prefixes. SeaweedFS is used only for local development.
- **Keycloak**: OIDC authorization code with PKCE, mandatory local OTP flow, server-side token verification.

The local stack is bound to loopback. Its private Docker network uses plaintext internal transport and local development credentials. The separate cloud configuration requires TLS to external backing services. The reference pilot has single points of failure and makes **no high-availability claim**.

## Repository

```text
backend/secops/         Domain services, HTTP API, authentication, adapters, workers
backend/migrations/    Versioned SQL migrations
backend/tests/         Dependency-free domain/persistence/adapter tests
backend/integration/   HTTP and real-service integration tests
frontend/              Next.js console and Playwright tests
fixtures/              Explicitly synthetic normalized/Windows/Linux examples
collectors/            Maintained-collector configuration examples
infra/                 TLS edge, cloud VM deployment, monitoring and backup templates
scripts/               Local setup, synthetic sender, encrypted backup
docs/                  Architecture, API, security, operations and feature status
.github/workflows/     CI, dependency/container scanning and integration checks
```

## Validate

```bash
cd backend
python -m unittest discover -s tests -t . -v
pip install -r requirements.txt
python -m unittest integration.test_api -v
```

From the repository root with Docker services healthy:

```bash
docker compose exec -e RUN_STACK_TESTS=1 api python -m unittest integration.test_stack -v
cd frontend
npm install
npm run typecheck
npm run build
npx playwright install chromium
npm run test:browser
```

See [validation](docs/VALIDATION.md) for what has actually run. Configuration parsing and unit tests do not establish that a container deployment or identity flow works. See [feature status](docs/STATUS.md) for implemented, unvalidated, and deferred work.

## Documentation

- [Implementation plan and architecture](docs/ARCHITECTURE.md)
- [API contracts and event schema](docs/API.md); runtime OpenAPI at `/api/openapi.json` and interactive reference at `/api/docs`
- [Security model and known gaps](docs/SECURITY.md)
- [Operator and administrator guide](docs/OPERATIONS.md)
- [Collector contracts and limitations](docs/COLLECTORS.md)
- [Detection catalog and behavior](docs/DETECTIONS.md)
- [Cloud deployment and rollback](docs/DEPLOYMENT.md)
- [Backup and restore procedure](docs/BACKUP_RESTORE.md)
- [Official version/license references](docs/DEPENDENCIES.md)

Cloud provider, region, budget, domain, and authorized identity/storage services are needed before actual provisioning. The supplied Ansible/Compose reference deploys to an operator-supplied VM; it does not create infrastructure or incur cloud charges by itself.