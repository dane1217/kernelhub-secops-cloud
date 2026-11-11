# Dependency and license review

Checked against current official documentation on 2026-11-11. Runtime integration/build validation is a separate gate; a documented version does not prove the whole stack was installed successfully on this host. Direct dependencies/image versions are pinned; complete transitive locks and image digests must be captured from a successful network-enabled build before production. CI uploads resolved Python and npm versions for review.

| Component | Selected line/version | License / integration note | Primary reference |
|---|---|---|---|
| Python | 3.12 container | PSF; same major used by local tests | [Python](https://www.python.org/downloads/)
| Next.js | 16.4.6 | MIT; 16.x active LTS, Node >=20.9; Node 24 selected | [Support](https://nextjs.org/support-policy), [release](https://github.com/vercel/next.js/releases/tag/v16.4.6)
| React | 19.3.0 | MIT; supported client UI line | [Versions](https://react.dev/versions)
| FastAPI | 0.162.4 | MIT; Pydantic v2 request validation | [Release notes](https://fastapi.tiangolo.com/release-notes/), [project license](https://github.com/fastapi/fastapi/blob/master/LICENSE)
| Pydantic | 2.14.2 | MIT; also present in host runtime | [Project](https://pypi.org/project/pydantic/)
| Uvicorn | 0.54.0 | BSD-3-Clause; ASGI; query access logs disabled | [Project](https://pypi.org/project/uvicorn/)
| PostgreSQL | 18.6 | PostgreSQL License; supported major through 2030 | [Version policy](https://www.postgresql.org/support/versioning/), [license](https://www.postgresql.org/about/licence/)
| Psycopg | 3.3.8 | LGPL-3.0-or-later; separate DB-API driver | [Downloads](https://www.psycopg.org/download/), [license](https://www.psycopg.org/psycopg3/docs/basic/install.html)
| OpenSearch | 3.9.0 | Apache-2.0; REST adapter validates TLS and tenant index/filter | [Download](https://opensearch.org/downloads/), [Docker](https://docs.opensearch.org/latest/install-and-configure/install-opensearch/docker/)
| Celery | 5.7.0 | BSD-3-Clause; JSON tasks, late ACK, idempotent SQL outbox | [Stable docs](https://docs.celeryq.dev/en/stable/), [Redis transport](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html)
| Redis | 8.4.8 | Select permitted Redis license: AGPLv3 / RSALv2 / SSPLv1; review distribution/service terms | [Licenses](https://redis.io/legal/licenses/), [releases](https://download.redis.io/releases/)
| Keycloak | 26.8.2 | Apache-2.0; chosen OIDC provider; code/PKCE, OTP realm flow | [Downloads](https://www.keycloak.org/downloads), [container](https://www.keycloak.org/server/containers), [OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers)
| PyJWT | 2.15.1 | MIT; fixed RS256 algorithm allowlist and JWKS verification | [Project](https://pypi.org/project/PyJWT/)
| boto3 | 1.43.30 | Apache-2.0; S3 API, tenant key validation, production SSE-S3 | [Project](https://pypi.org/project/boto3/1.43.30/), [S3 encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html)
| SeaweedFS | 4.53 | Apache-2.0; local S3-compatible service only | [Project](https://github.com/seaweedfs/seaweedfs), [release](https://github.com/seaweedfs/seaweedfs/releases/tag/4.53)
| HTTPX | 0.28.1 | BSD-3-Clause; HTTP integration tests | [Project](https://www.python-httpx.org/)
| Prometheus client | 0.26.0 | Apache-2.0 AND BSD-2-Clause; private aggregate metrics | [Project](https://pypi.org/project/prometheus-client/)
| Caddy | 2.10.2 | Apache-2.0; TLS edge and private route filtering | [Docs](https://caddyserver.com/docs/)
| Docker / Compose | Host installation | Engine/Compose are open source; Docker Desktop has separate subscription terms | [Install](https://docs.docker.com/engine/install/), [Desktop terms](https://docs.docker.com/subscription/desktop-license/)

No major stack replacement was made. S3 is represented locally by Apache-licensed SeaweedFS to avoid embedding a commercial intelligence/storage service into development. No intelligence data license is assumed. The repository itself deliberately has no public open-source license grant; KernelHub must decide its source distribution terms.

Follow Dependabot/renovation policy, scan both transitive dependencies and built images, review license notices/SBOMs and rebuild for security updates. A scan failure blocks promotion; do not disable checks to produce a green badge. Floating base-image patch tags remain a reproducibility gap until resolved to digest.
