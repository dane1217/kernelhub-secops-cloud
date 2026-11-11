# Validation record

Initial implementation date: 2026-11-11.

| Check | Observed result |
|---|---|
| GitHub repository inspection | Empty private repository; authenticated read/write/admin permission verified |
| Dependency-free domain/persistence/adapter suite | 22 unique tests passed on bundled Python 3.12, Windows amd64; includes positive/negative subtests for ten detections and safe logging |
| Python syntax compilation | Passed for backend and scripts |
| Local Compose configuration | `docker compose config --quiet` passed with generated development configuration |
| Local Docker CLI / Compose discovery | Docker 29.9.2 client and Compose 5.6.1 detected |
| Container engine access | Blocked: permission denied connecting to Docker Desktop Linux named pipe from this execution session |
| Shell Git clone / dependency installation | Shell networking unavailable; GitHub clone could not resolve host; pip could not resolve requested dependencies |
| HTTP integration | Passed in GitHub Actions run 43073895375 (three HTTP contract tests); not run locally |
| Frontend typecheck / production build / dependency audits | Passed in GitHub Actions run 43073895375; not run locally |
| Browser tests | Pending container job; no successful outcome claimed yet |
| Real PostgreSQL/OpenSearch/S3 pipeline | Passed in GitHub Actions run 43074518662: five persisted/indexed/archived events, evidence-backed alert and isolated second organization |
| OIDC OTP / cloud deployment / restore | Not run successfully yet; no successful outcome claimed |
| Measured production capacity | None; no EPS, tenant capacity, latency, RPO or RTO claim |

The domain suite uses SQLite transactions and test-only in-memory search/object adapters. It verifies authorization, scope revocation, invitation binding, credential separation, atomic ingestion/quota failures, redaction, source revocation, duplicate delivery, durable restart recovery, search outage/retry/dead letters, evidence-bearing alerts, late source-time correlation, rule disabling, incident transitions and audit immutability. PostgreSQL concurrency, actual worker termination, external-service security and OIDC behavior require the separate integration/drill tests.

CI jobs define dependency installation/scanning, domain tests, HTTP integration tests, frontend typecheck/build/audit, actual Compose services, S3/index/detection integration, Playwright UI checks and container scans. [Initial run](https://github.com/dane1217/kernelhub-secops-cloud/actions/runs/43073895375) passed backend and frontend jobs; its container job failed before execution because an action tag was invalid. The tag was corrected to the verified v0.36.0 release. [The next run](https://github.com/dane1217/kernelhub-secops-cloud/actions/runs/43074518662) passed the real-service pipeline test, then hit Playwright's unsupported Ubuntu 26.04 runner. The workflow now pins Ubuntu 24.04, matching the selected Playwright line, and includes a real OIDC/OTP acceptance test. Those browser and scan results are still pending.

`frontend/package-lock.json` and `backend/constraints.txt` were captured from successful network-enabled CI resolution for the initial implementation. The Python constraints also include test/audit tooling; unused constraints do not install those tools in runtime images. This is a version constraint lock, not a hash-verified Python artifact lock. Base/container image digest pinning and platform-specific dependency validation are still required before production.

For load testing, record CPU/RAM/disk/OS, container/image/dependency versions, event-size distribution, sources/tenants, sustained and burst delivery, duplicate percentage, worker concurrency, query time ranges/filters/pagination, ingestion/index lag, query latency and errors under service failure. Do not extrapolate a tiny functional fixture into capacity. No load generator or capacity result is delivered in this first slice.
