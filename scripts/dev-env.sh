#!/usr/bin/env bash
# Development environment: PostgreSQL, Loki, the OpenPicket CrowdSec image
# and openpicket-suricontroller with docker compose
# (deploy/dev/docker-compose.yml), and openpicket-manager on the host
# (http://127.0.0.1:${PORT:-18090}, admin / openpicket-dev).
#
#   scripts/dev-env.sh [up]     start the dependencies, then the manager
#                               (Ctrl-C stops the manager only)
#   SEED=1 scripts/dev-env.sh   also feed sample records to CrowdSec
#   scripts/dev-env.sh build    rebuild the CrowdSec and suricontroller
#                               images (built once when missing)
#   scripts/dev-env.sh seed     feed sample records
#   scripts/dev-env.sh logs     follow the dependencies' logs
#   scripts/dev-env.sh down     remove the dependencies and their data
set -euo pipefail
cd "$(dirname "$0")/.."
compose() { docker compose -f deploy/dev/docker-compose.yml "$@"; }
# --network host: the default build network has no working DNS on some
# hosts.
build() {
  docker build --network host -f deploy/images/crowdsec/Dockerfile -t openpicket-crowdsec:dev .
  docker build --network host -f deploy/images/suricontroller/Dockerfile -t openpicket-suricontroller:dev .
}
PORT="${PORT:-18090}"

case "${1:-up}" in
  up) ;;
  build) build; exit ;;
  seed) exec ./scripts/dev-seed.sh ;;
  logs) compose logs -f ;;
  down) compose down -v; exit ;;
  *) sed -n '2,16s/^# \{0,1\}//p' "$0"; exit 2 ;;
esac

mkdir -p bin
[ -f bin/dev-host-key ] || go run ./cmd/openpicket-manager keygen > bin/dev-host-key 2>/dev/null
export OPENPICKET_HOST_KEY_FILE="$PWD/bin/dev-host-key"
# suricontroller verifies the manager's tokens with this key.
OPENPICKET_DEV_PRINCIPAL_KEY="$(go run ./cmd/openpicket-manager principal-pubkey)"
export OPENPICKET_DEV_PRINCIPAL_KEY

for img in openpicket-crowdsec:dev openpicket-suricontroller:dev; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "building images..."; build; break; }
done
echo "starting dependencies..."
compose up -d --wait
# CrowdSec has no content until it gets some: the built-in one now, the
# manager's (revision of the database) once it runs.
go run ./cmd/openpicket-manager hub-bundle | compose exec -T crowdsec openpicket-crowdsec-sync put >/dev/null
for _ in $(seq 1 60); do
  compose exec -T crowdsec cscli lapi status >/dev/null 2>&1 && break
  sleep 1
done
[ "${SEED:-0}" = 1 ] && ./scripts/dev-seed.sh

export OPENPICKET_LISTEN="127.0.0.1:${PORT}"
export OPENPICKET_METRICS_LISTEN="127.0.0.1:$((PORT + 1))"
export OPENPICKET_DATABASE_URL="postgres://postgres:dev@127.0.0.1:15432/postgres?sslmode=disable"
export OPENPICKET_LOKI_URL="http://127.0.0.1:13100"
export OPENPICKET_CROWDSEC_ENDPOINTS="http://127.0.0.1:18081/openpicket"
export OPENPICKET_CROWDSEC_AUTH_HEADER="X-OpenPicket-Token"
export OPENPICKET_CROWDSEC_AUTH_VALUE="dev-token"
export OPENPICKET_CROWDSEC_SYNC_ENDPOINTS="http://127.0.0.1:18083"
export OPENPICKET_CROWDSEC_METRICS_URLS="http://127.0.0.1:16060/metrics"
export OPENPICKET_LAPI_URL="http://127.0.0.1:18080"
export OPENPICKET_LAPI_BOUNCER_KEY="dev-bouncer-key"
export OPENPICKET_LAPI_LOGIN="openpicket-manager"
export OPENPICKET_LAPI_PASSWORD="dev-password"
export OPENPICKET_SURICONTROLLER_URL="http://127.0.0.1:18082"
export OPENPICKET_ADMIN_USERNAME=admin
export OPENPICKET_ADMIN_PASSWORD=openpicket-dev
export OPENPICKET_INSECURE_COOKIES=true
export OPENPICKET_PUBLIC_URL="http://127.0.0.1:${PORT}"
echo "openpicket-manager on http://127.0.0.1:${PORT} (admin / openpicket-dev); 'scripts/dev-env.sh down' removes the dependencies"
exec go run ./cmd/openpicket-manager serve
