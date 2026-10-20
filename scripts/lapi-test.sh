#!/usr/bin/env bash
# Runs the LAPI integration tests (test/lapi_test.go) against the OpenPicket
# CrowdSec image and a throwaway PostgreSQL: the watcher client, the alert
# copy and the bouncer stream with a real LAPI.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-openpicket-crowdsec:dev}"
name="openpicket-lapi-test-$$"
docker run -d --rm --name "$name" -e OPENPICKET_ACQUIS_TOKEN=test-token -p 127.0.0.1::8080 -p 127.0.0.1::8081 "$IMAGE" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
ex() { docker exec "$name" "$@"; }
wait_lapi() {
  for _ in $(seq 1 90); do
    ex cscli lapi status >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$name" | tail -40
  echo "FAIL: crowdsec did not start"; exit 1
}
wait_lapi
# Deleting alerts is restricted to trusted_ips; the test reaches the LAPI
# through the docker gateway.
ex yq -i '.api.server.trusted_ips = ["127.0.0.1", "::1", "0.0.0.0/0", "::/0"]' /etc/crowdsec/config.yaml
docker restart "$name" >/dev/null
wait_lapi
ex cscli machines add openpicket-manager --password lapi-test-password --force -f /tmp/m.yaml >/dev/null
ex cscli bouncers add openpicket-relay -k lapi-test-bouncer-key >/dev/null
port() { docker port "$name" "$1/tcp" | head -1 | sed 's/.*://'; }
export OPENPICKET_TEST_LAPI_URL="http://127.0.0.1:$(port 8080)"
export OPENPICKET_TEST_LAPI_LOGIN=openpicket-manager
export OPENPICKET_TEST_LAPI_PASSWORD=lapi-test-password
export OPENPICKET_TEST_LAPI_BOUNCER_KEY=lapi-test-bouncer-key
export OPENPICKET_TEST_ACQUIS_URL="http://127.0.0.1:$(port 8081)/openpicket"
export OPENPICKET_TEST_ACQUIS_TOKEN=test-token
COUNT=1 ./scripts/test-pg.sh ./test/ -run LAPI -v
