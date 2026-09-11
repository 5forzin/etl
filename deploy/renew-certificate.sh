#!/usr/bin/env bash
set -euo pipefail
[[ "${RENEWED_LINEAGE:-}" == /etc/letsencrypt/live/etl ]] || exit 0
install -m 600 -o 1000 -g 1000 "$RENEWED_LINEAGE/fullchain.pem" /opt/etl/secrets/fullchain.pem
install -m 600 -o 1000 -g 1000 "$RENEWED_LINEAGE/privkey.pem" /opt/etl/secrets/privkey.pem
cd /opt/etl
docker compose restart etl
