# Operator and administrator guide

## Local development

Run `python scripts/setup.py` once, then `docker compose up --build -d --wait`. Setup refuses to overwrite existing `.env` or realm credentials. Keep `.env` and `.local/` private; both are ignored by Git. Do not print them into tickets or CI logs. The randomly generated pilot user is explicitly synthetic and exists only in the development realm.

Docker must use Linux containers. The stack needs a running Linux engine, sufficient memory, free disk space and a supported `vm.max_map_count` for OpenSearch (262144 minimum). On a Linux VM, set it with `sudo sysctl -w vm.max_map_count=262144` and persist the setting. Docker Desktop settings/WSL handling vary by installation; use Docker's current platform documentation.

Useful commands:

```bash
docker compose ps
docker compose logs --tail=100 api worker scheduler
docker compose exec api python -c "from secops.runtime import build; _,_,s=build(); s.search.health(); s.objects.health(); print('dependencies reachable')"
docker compose exec api python -m secops.manage reindex
```

Reindex reads authoritative SQL events and upserts their stable IDs. It does not rerun rules or recreate incidents. Never publish PostgreSQL, Redis, S3, OpenSearch or private metrics ports to the Internet.

## Administrator workflow

Create an organization as the configured platform administrator. This creates its default workspace and explicitly adds the creator as organization administrator. Add a source with the correct parser, securely save its one-time credential, and distribute it to a collector. Use separate sources/credentials for independently managed systems. Source creation/rotation uses the API or Integrations screen; rotation currently means create a replacement source and revoke the old source. A changed source ID changes the deduplication scope, so coordinate collector cutover.

Invite users by their identity-provider **verified email**, assign exactly one role and share the one-time 48-hour invitation securely. Users sign in, then accept the invitation code. The API also permits already-assigned users to accept additional invitations. The UI acceptance form is currently shown when no organization is assigned; assigned analysts use POST `/api/invitations/accept` for additional organizations. Do not share an administrator session to grant analyst access.

API credentials are created through POST `/api/orgs/{org}/credentials` and shown once. Their role is a cap, never an elevation over current membership. Revoke through `/credentials/revoke`; membership removal invalidates owned organization credentials. The last administrator cannot be removed or downgraded through invitation acceptance.

## Analyst workflow

Check event freshness, pending/dead jobs and source parser failures before assuming there is no threat activity. Open an alert, inspect its rule/tuning snapshot and supporting events, assign it and record triage. Create an incident from one or more same-organization alerts (the API supports grouping). Follow the documented lifecycle; add attributed notes, task text, evidence notes and feedback. Resolution requires a category and should include a useful customer-facing summary.

Customer reports include the incident title, severity, status, resolution, created time and customer summary. They do not include arbitrary analyst notes. Authorized viewers can inspect underlying alerts/evidence in their organization. Reports are JSON in this release, not generated PDF documents.

## Pipeline troubleshooting

| Symptom | Check / recovery |
|---|---|
| 401 ingestion | Correct source key, expiry and revocation; analyst API keys cannot ingest |
| 422 ingestion | Batch array/field limits, timestamp timezone, parser kind, Windows structured fields; parser failure audit/counter |
| 429 | 1,000 delivered events/minute and 100,000 new stored events/day per tenant by default; back off and preserve IDs |
| 503 backpressure | Pending outbox is at 10,000 tenant jobs; restore workers/dependencies before retry |
| Accepted but not searchable | Check scheduler/worker heartbeat, S3 and OpenSearch; 202 only means committed to SQL |
| Dead letter | Inspect safe error code and event provenance; fix dependency, then replay exact org/job through the authorized endpoint |
| Search unavailable | API returns 503; ingestion continues until backpressure ceiling |
| Missing alert | Check action, required fields, enabled/tuned rule, exclusions, historical flag, source window and processing backlog |
| Missing telemetry | Compare last_seen to expected source cadence; no event means there may be no source activity |

Retries are two-to-256-second exponential delays, bounded to 300 seconds by implementation, with eight failed external attempts before dead-lettering. Both archive and indexing use stable targets. Restart workers normally with `docker compose restart worker`; a hard termination must be tested separately. Redis AOF is fsynced once a second, but SQL outbox jobs are independently durable. If Redis loses tasks, the scheduler drains remaining SQL jobs again.

The worker heartbeat is the SQL scheduler-task execution timestamp, not proof that every tenant is current. A scheduler queue can also be stalled. Poll private metrics and scrape database/source freshness; install `infra/alerts.yml` in your own Prometheus. No Prometheus server or notification destination is provisioned automatically. Outage and missing-telemetry notifications are Phase 2 work.

## Retention, deletion and storage

The organization retention setting defaults to 30 days and is **not automatically enforced yet**. Do not onboard production personal data until deletion workflows are implemented and validated across SQL, search, S3, incident evidence and audit policy. There is no storage-byte cap; event/day, event/minute, body/event and pending-job caps do not prevent eventual disk exhaustion. Track host disk, database growth and object/search storage externally.

Do not install an S3 lifecycle that deletes active evidence independently. The target policy is: expire ordinary raw/indexed telemetry after the selected tenant retention, preserve evidence only under an explicit incident/legal-hold policy, then delete the corresponding SQL/search/object records idempotently with audited checkpoints. Apply S3 lifecycle as a safety margin after that workflow exists. Tenant-wide deletion and backup-expiry accounting are pending; backups retain data independently until their own retention expires.

Do not truncate audit or event tables as a routine recovery shortcut. Use a fresh isolated environment for restore drills. See [backup and restore](BACKUP_RESTORE.md).
