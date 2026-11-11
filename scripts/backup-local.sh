#!/usr/bin/env bash
# Reference local-pilot backup; needs age and Docker. Never runs automatically on install.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${AGE_RECIPIENT:?set the public encryption recipient}"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
chmod 700 backups
trap 'docker compose start objects api worker scheduler >/dev/null' EXIT
docker compose stop scheduler worker api objects
docker compose exec -T postgres pg_dump -U postgres -Fc secops | age -r "$AGE_RECIPIENT" > "backups/$stamp-secops.dump.age"
docker compose exec -T postgres pg_dump -U postgres -Fc keycloak | age -r "$AGE_RECIPIENT" > "backups/$stamp-keycloak.dump.age"
tar -cf - .env .local | age -r "$AGE_RECIPIENT" > "backups/$stamp-config.tar.age"
docker run --rm --network none -v kernelhub-secops_objectdata:/data:ro alpine:3.22 tar -C /data -cf - . | age -r "$AGE_RECIPIENT" > "backups/$stamp-objects.tar.age"
printf '%s\n' "Encrypted backup set created: $stamp. Copy off-host and verify a restore."
