# Security model and release gates

## Tenant boundaries

The authenticated principal maps to a database user and current organization membership. Platform administration is distinct from customer data access. Machine credentials also bind an organization and maximum role; every request rechecks membership. Ingestion credentials bind organization, workspace and source and cannot call analyst APIs. No submitted tenant ID selects an ingestion tenant.

Relational queries have explicit organization predicates; cross-resource links use composite tenant foreign keys. OpenSearch indexes use UUID organization names plus mandatory tenant filters, and returned hits are checked again. S3 writes validate a canonical organization prefix. Exports use the same authorized search path. There is no cross-tenant cache; responses are no-store. Workspaces inherit organization access.

Tenant-isolation tests cover search, events/raw evidence, alerts, incidents, membership lists, rules, workspaces, sources, audit, overview, API credential scope, object prefixes and composite relationships. These tests do not replace an independent penetration test. PostgreSQL RLS and per-tenant database/search credentials are not implemented: service compromise can expose multiple tenants. Treat backend service credentials as highly privileged infrastructure secrets.

## Authentication and sessions

Keycloak provides OIDC and OTP. Login uses authorization code + S256 PKCE, one-use state bound to an HttpOnly browser cookie, nonce, issuer/audience/expiry checks, RS256 only, and verified-email requirements. ID/access tokens are never returned to the browser or persisted. Application sessions use random 256-bit tokens; only SHA-256 hashes are stored. Sessions expire after 30 minutes; cookies are HttpOnly, SameSite=Lax and Secure outside development.

Cookie mutations require an exact allowed Origin and a session CSRF token. OIDC callback uses state/nonce instead. Local sign-out invalidates the application session; it does not globally terminate the identity-provider SSO session. Upstream account suspension is not reflected immediately in an existing application session; maximum exposure is its 30-minute lifetime, while local membership revocation takes effect on the next request. Backchannel logout and centralized session revocation UI are deferred.

The local generated realm forces an OTP form and enrollment. Imported realm behavior still needs a real browser login test. For an external realm, the operator MUST enforce MFA, verified email, no open self-registration, exact redirect URIs, confidential client authentication, S256 PKCE, brute-force protection, and RS256. Do not use a hard-coded MFA claim to pretend the provider enforced a second factor. The bootstrap administrator is an explicit immutable provider subject configured out of band, never the first visitor or a matching email address.

Invitations are random, hashed, one-use, expire after 48 hours and bind the logged-in verified email. Creating invitations does not send messages. The administrator shares them securely. Source credentials expire after 90 days; org-scoped API credentials after seven days. Credentials are shown once and can be revoked. No passwords or reversible ingestion keys are stored.

## Data protection

Known sensitive keys and common key=value secret patterns are redacted before persistence and archive. This is not a general-purpose DLP engine: unknown secrets or personal data embedded in free text can remain. Minimize telemetry at the collector and review samples before enabling production sources. There is no exposure-provider ingestion or leaked-password handling in this phase.

All collector content is data. React text rendering escapes it; the backend never evaluates log code, queries, templates or embedded instructions. Search is an allowlist API. Playbooks, remote shell execution and external AI calls do not exist in this slice.

Deployment rejects non-PostgreSQL runtime databases. Staging/production require HTTPS service endpoints, verified PostgreSQL TLS and rediss. Managed service CA certificates must be correctly mounted or publicly trusted. Use provider-encrypted volumes, database encryption, S3 default encryption and restricted IAM. Cloud S3 writes request SSE-S3. Local SeaweedFS does not enable at-rest encryption; local Docker volumes and plaintext internal transport are development-only.

## Audit and service credentials

Audit is a separate relational table. Immutable triggers reject UPDATE/DELETE, and the runtime database role lacks schema ownership and audit mutation privileges. Migrations use a distinct privileged credential. Infrastructure/database administrators can still alter or bypass local audit protection; this is not a tamper-proof external ledger. Independent immutable audit export and signed evidence manifests are pilot-hardening backlog items.

Runtime PostgreSQL requires table SELECT/INSERT/UPDATE/DELETE except audit (SELECT/INSERT only) and no schema_migrations privileges. Never run the API as PostgreSQL superuser or migration owner. Local initialization creates separate runtime, migration and Keycloak users. Cloud operators must create the same roles and default grants before migrations.

The OpenSearch runtime account needs create/index/read permissions limited to `kh-events-*`; never use a shared administrative account. S3 permissions are restricted to the configured event bucket and tenant prefixes wherever workload IAM allows. Workers currently serve all tenants; the shared worker role needs all assigned prefixes. Redis has a password, no published port and noeviction/AOF settings. Disable unneeded Redis administration commands with tested ACLs in production; Celery command requirements must be verified first.

No tenant-configurable outbound URL is supported. Adapter URLs come from protected deployment configuration; redirects are disabled on custom HTTP calls. Enrichment SSRF protection, licensed provider access and action-specific approvals must be designed before those later integrations are enabled.

## Outstanding release gates

- Run HTTP, OIDC/OTP, browser, PostgreSQL/OpenSearch/S3, worker-termination and restore tests on a Docker-capable host.
- Resolve dependency/container scan findings; commit full transitive locks and immutable image digests from a successful build before production.
- Add per-tenant retention/deletion across SQL/search/S3, including evidence/legal-hold policy; current retention value is a target only.
- Confirm network egress ACLs, TLS certificates, at-rest encryption, backup encryption and recovery drill.
- Add authentication failure/security monitoring, centralized sanitized error reporting, CSP with nonces, API request metrics and denied-access audit coverage.
- Limit S3/database byte growth as well as event counts. Implement audit retention/export independently.
- Perform accessibility/focus and independent security review. Modal focus management is not yet fully validated.

There is no regulatory certification, compliance attestation, high-availability claim, complete dark-web coverage, live AI or tested disruptive response integration.
