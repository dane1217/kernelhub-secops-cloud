# Deployment and rollback

## Environments

| Environment | Configuration | Boundary |
|---|---|---|
| Development | `compose.yaml`, generated `.env` + `.local` | Loopback edge; isolated Docker backing services; local HTTP/unencrypted volumes |
| Staging | `infra/compose.cloud.yaml`, external `.env.cloud`, APP_ENV=staging | Dedicated VM/service credentials/databases/buckets/realm; TLS enforced |
| Production | Same reference with APP_ENV=production | Separate identities, secrets, backups, domains and databases; release gates required |

Never reuse development credentials or copy synthetic users into production. The application refuses plaintext HTTP backing endpoints, non-verified PostgreSQL TLS and plaintext Redis URLs in staging/production. The edge-to-local-container hop is confined to the private application network on the same VM; external backing services use authenticated TLS. For multiple VMs use private routing and TLS on every inter-host hop.

## Cloud reference, without provisioning

The repository supplies Ansible IaC for an already-authorized Ubuntu VM and container configuration for externally provisioned PostgreSQL, Redis, OpenSearch, S3 and Keycloak. It does not provide Terraform for an arbitrary cloud or assume access to existing KernelHub servers. Actual VM/service creation, DNS, security groups and encryption keys require provider, region, budget, domain and explicit provisioning access.

Before deploying:

1. Pass all checks listed in `STATUS.md`, commit resolved dependency locks and replace base/application image tags with verified immutable digests in the release manifest. Build and scan API/web images; publish them to the chosen private registry using your approved credentials.
2. Supply a patched Docker/Compose host, firewall inbound 443 (and 80 for ACME) only, restricted SSH access, encrypted disk, monitoring and off-host backups. Restrict egress to authorized identity, database, search, object and broker services and required DNS/time/ACME endpoints.
3. Create private backing services and least-privilege runtime/migration credentials. Create `secops_migration` as owner and `secops_app` as runtime user; grant schema CREATE to migration and default table SELECT/INSERT/UPDATE/DELETE to runtime, matching local initialization. Migrations revoke audit mutations and all schema_migrations access from runtime. Keycloak uses its own database/credentials.
4. Create a verified-TLS OpenSearch endpoint with runtime permissions limited to `kh-events-*` index creation/indexing/read. Single-node indexes currently set replicas=0. A cluster, replica policy, shard planning and tested failover require a separate change.
5. Create an encrypted, private S3 bucket with restricted IAM and versioning/backup policies. Runtime needs PutObject and readiness ListBucket/HeadBucket permissions; recovery needs separate GetObject privileges. Do not silently expire retained incident evidence.
6. Configure a Keycloak realm/client with exact redirect `https://YOUR_DOMAIN/auth/callback`, RS256, confidential client auth, S256 PKCE, verified emails and MFA. Obtain the intended initial platform administrator's immutable subject and set BOOTSTRAP_SUBJECT. Its first valid login creates that application identity. Keep registration closed.
7. Prepare `.env.cloud` from `.env.example` **outside source control**. Use a secret manager or encrypted Ansible Vault source. Set APP_IMAGE, WEB_IMAGE, RELEASE_TAG, DOMAIN and ACME_EMAIL. Use publicly trusted service certificates or add read-only CA mounts in the Compose deployment and corresponding PostgreSQL/Redis/AWS CA settings. The supplied cloud file has no custom CA mounts by default.
8. Authenticate the VM to the private registry using an approved credential store. Run `ansible-playbook -i infra/inventory.ini infra/deploy.yml -e secret_env_file=/secure/path/.env.cloud`. No cloud resources are created automatically.

Equivalent manual deployment, in a protected directory containing the reference cloud files and secrets:

```bash
docker compose --env-file .env.cloud config --quiet
docker compose --env-file .env.cloud pull
docker compose --env-file .env.cloud run --rm migrate
docker compose --env-file .env.cloud up -d --wait api web worker scheduler edge
```

Use `infra/compose.cloud.yaml` as that directory's `compose.yaml`. Caddy's certificate volumes must be durable. DNS must point to the VM, and ACME challenge access must be available. This is a reference; no real domain, TLS certificate or VM was deployed during initial implementation.

## Release verification

Check live and private ready endpoints, worker heartbeat and source freshness. Perform the synthetic acceptance scenario in an isolated staging organization, inspect actual archive objects and alerts, resolve an incident, export records and test a second tenant. Verify invalid credentials, parser failure, duplicates, dependency outage and recovery. Kill/restart a processing worker and prove no accepted data or alert duplication is lost. Run a fresh-environment backup restore drill. Record exact image digests, schema version, dependency locks, hardware and test evidence before promoting a release.

## Rollback

Retain the previously tested release tag/digests and encrypted pre-release backups. Migrations must remain compatible with both old and new application versions for rolling application rollback. Migration 001 is initial/additive; it has no automatic destructive down migration.

To roll back an application release, set RELEASE_TAG to the previous reviewed version and rerun pull/up for api/web/worker/scheduler. Do not run a destructive schema rollback in place. If a migration is incompatible or corrupts data, stop writes and restore the pre-release database/object backup into a fresh isolated deployment, verify it, then switch the edge/DNS through the approved incident procedure. Data accepted after the recovery point must be replayed from preserved collector buffers where available; no zero-data-loss promise is made.
