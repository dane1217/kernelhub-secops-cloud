# Backup and restore

**Initial status: scripts and drill procedure supplied; no real restore drill has passed yet.** Production onboarding is blocked until recovery is validated. Database persistence or a Docker volume alone is not a backup.

## Local reference backup

`scripts/backup-local.sh` requires Docker, a Linux/WSL shell and the `age` encryption CLI. It pauses ingestion/workers/object storage, takes PostgreSQL custom dumps of the application and Keycloak databases, encrypts private configuration and archives the stopped SeaweedFS volume. The fixed local project name is `kernelhub-secops`; adapt the volume name if you change it. Search is recoverable from PostgreSQL and is not snapshotted. The Redis queue is recoverable from the SQL outbox and is not a recovery source.

Set AGE_RECIPIENT to an approved **public** age recipient; keep its private decryption identity in a separate recovery vault, off this host. Run the script and copy the entire encrypted set off-host. Restrict access to backups: they contain customer telemetry, identity credentials and audit data even when encrypted. A trap restarts paused services if the script fails; verify service health yourself.

The optional systemd service/timer schedules daily 02:00 UTC backups with small jitter. Installing/enabling it is an operator action, not done by setup. Its working directory assumes the local pilot Compose layout, **not** the external-service cloud layout. Cloud backing services need provider-native encrypted backups, versioned object recovery and a separately tested recovery plan. Keycloak backups must include its database and signing keys/configuration.

## Restore drill: fresh isolated environment only

Never point this procedure at a production volume or database. Prepare a fresh checkout/directory and use project name `secops-restore`. Verify no volume named `secops-restore_pgdata` or `secops-restore_objectdata` exists before beginning; choose another unique name if it does. Do not delete an existing volume to make this procedure fit.

1. Decrypt the saved config archive into the fresh directory. It contains `.env` and `.local/`; protect these files with owner-only permissions. Do not run setup again or overwrite restored secrets. Use the saved age identity from the recovery vault.
2. Start only PostgreSQL: `docker compose -p secops-restore up -d postgres`. Wait for `pg_isready`. The restored initialization SQL creates runtime/migration/Keycloak roles with the saved passwords and initially empty databases.
3. Restore each custom dump to its corresponding initially empty database:

```bash
age -d -i /secure/recovery-identity backups/SET-secops.dump.age | docker compose -p secops-restore exec -T postgres pg_restore -U postgres -d secops --exit-on-error
age -d -i /secure/recovery-identity backups/SET-keycloak.dump.age | docker compose -p secops-restore exec -T postgres pg_restore -U postgres -d keycloak --exit-on-error
```

4. Restore the encrypted object tar to the fresh object volume before starting SeaweedFS:

```bash
age -d -i /secure/recovery-identity backups/SET-objects.tar.age | docker run --rm -i --network none -v secops-restore_objectdata:/data alpine:3.22 tar -C /data -xf -
docker compose -p secops-restore up -d objects opensearch redis
docker compose -p secops-restore run --rm api python -m secops.manage reindex
```

5. Start workers and API internally without starting the public edge. Validate SQL tenant/event/alert/incident/audit counts against pre-backup checks and head/get selected tenant archive objects. Verify an existing incident's rule snapshot, evidence IDs, timestamps and timeline. Run the real-service integration test in an explicitly synthetic drill organization.
6. If a browser drill is required, ensure the original local edge is stopped or use a separate isolated machine; its imported realm has a strict localhost:8080 callback. Start the drill Keycloak/web/edge only in that isolated setting. Verify the restored user/password/OTP and independent-tenant boundaries.
7. Record backup timestamp, start/end time, counts/hashes checked, recovery-point gap, recovery duration and observed failures. Treat recovery time and recovery point as **measured results only after this drill**, never assumed targets.

This procedure intentionally does not issue volume deletion or overwrite commands. Teardown and disposal of restored customer data require an operator-approved retention policy.

## Backup retention and deletion

Suggested pilot policy to approve: daily encrypted sets for 14 days, weekly sets for eight weeks, quarterly recovery drills and off-host copies in a distinct security boundary. This is a proposed policy, not an enabled lifecycle. An operator must implement expiration and monitor backup failures.

Deleting live tenant data will not immediately remove it from immutable/versioned backups. Keep a deletion ledger and reapply completed deletions after restore before allowing user access. Backup retention, legal holds and recovery access must be documented separately from active event retention. Automated live deletion and restore-time deletion reapplication are not implemented yet.
