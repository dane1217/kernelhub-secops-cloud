# Validation record

Initial implementation date: 2026-11-11.

| Check | Observed result |
|---|---|
| GitHub repository inspection | Empty private repository; authenticated read/write/admin permission verified |
| Dependency-free domain/persistence/adapter suite | 20 unique tests passed on bundled Python 3.12, Windows amd64; includes positive/negative subtests for ten detections |
| Python syntax compilation | Passed for backend and scripts |
| Local Compose configuration | `docker compose config --quiet` passed with generated development configuration |
| Local Docker CLI / Compose discovery | Docker 29.9.2 client and Compose 5.6.1 detected |
| Container engine access | Blocked: permission denied connecting to Docker Desktop Linux named pipe from this execution session |
| Shell Git clone / dependency installation | Shell networking unavailable; GitHub clone could not resolve host; pip could not resolve requested dependencies |
| HTTP integration, frontend typecheck/build, browser tests | Not run locally; dependencies unavailable |
| Real-service pipeline / OIDC OTP / cloud deployment / restore | Not run; no successful outcome claimed |
| Measured production capacity | None; no EPS, tenant capacity, latency, RPO or RTO claim |

The domain suite uses SQLite transactions and test-only in-memory search/object adapters. It verifies authorization, scope revocation, invitation binding, credential separation, atomic ingestion/quota failures, redaction, source revocation, duplicate delivery, durable restart recovery, search outage/retry/dead letters, evidence-bearing alerts, late source-time correlation, rule disabling, incident transitions and audit immutability. PostgreSQL concurrency, actual worker termination, external-service security and OIDC behavior require the separate integration/drill tests.

CI jobs define dependency installation/scanning, domain tests, HTTP integration tests, frontend typecheck/build/audit, actual Compose services, S3/index/detection integration, Playwright UI checks and container scans. Publishing this configuration does not imply a successful CI run. Record the exact run link and outcomes here when available.

For load testing, record CPU/RAM/disk/OS, container/image/dependency versions, event-size distribution, sources/tenants, sustained and burst delivery, duplicate percentage, worker concurrency, query time ranges/filters/pagination, ingestion/index lag, query latency and errors under service failure. Do not extrapolate a tiny functional fixture into capacity. No load generator or capacity result is delivered in this first slice.
