#!/usr/bin/env bash
# Runs the MISP client integration test (test/misp_test.go) against a
# throwaway MISP (misp-core with the misp-nginx front, MariaDB, Valkey).
# MISP takes a few minutes to initialise its database.
set -euo pipefail
cd "$(dirname "$0")/.."
id=$$
net="openpicket-misp-test-$id"
key="openpicketTestKey0000000000000000000000x"
docker network create "$net" >/dev/null
cleanup() { docker rm -f "misp-db-$id" "misp-redis-$id" "misp-core-$id" "misp-nginx-$id" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
trap cleanup EXIT
docker run -d --name "misp-db-$id" --network "$net" --network-alias db -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=misp \
  -e MYSQL_USER=misp -e MYSQL_PASSWORD=misp mariadb:10.11 >/dev/null
docker run -d --name "misp-redis-$id" --network "$net" --network-alias redis valkey/valkey:7.2 >/dev/null
docker run -d --name "misp-core-$id" --network "$net" --network-alias misp-core \
  -e BASE_URL=http://localhost -e ADMIN_EMAIL=admin@admin.test -e ADMIN_PASSWORD=OpenPicket-Test-1 -e ADMIN_KEY="$key" -e ADMIN_ORG=OpenPicket \
  -e MYSQL_HOST=db -e MYSQL_USER=misp -e MYSQL_PASSWORD=misp -e MYSQL_DATABASE=misp -e REDIS_HOST=redis -e ENABLE_REDIS_EMPTY_PASSWORD=true \
  -e DISABLE_IPV6=true -e MISP_MODULES_FQDN= -e NUM_WORKERS_DEFAULT=1 \
  -v "$PWD/deploy/misp/taxonomies/openpicket:/var/www/MISP/app/files/taxonomies/openpicket:ro" \
  "${IMAGE:-ghcr.io/misp/misp-docker/misp-core:latest}" >/dev/null
docker run -d --name "misp-nginx-$id" --network "$net" -p 127.0.0.1::8080 -e BASE_URL=http://localhost \
  -e FASTCGI_LISTEN=misp-core:9002 -e FASTCGI_LISTEN_STATUS=misp-core:9003 -e DISABLE_IPV6=true \
  "${NGINX_IMAGE:-ghcr.io/misp/misp-docker/misp-nginx:latest}" >/dev/null
port="$(docker port "misp-nginx-$id" 8080/tcp | head -1 | sed 's/.*://')"
echo "waiting for MISP on $port..."
for _ in $(seq 1 180); do
  if curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: $key" -H 'Accept: application/json' "http://127.0.0.1:$port/servers/getVersion" | grep -q 200; then
    ready=1; break
  fi
  sleep 5
done
if [ -z "${ready:-}" ]; then docker logs "misp-core-$id" 2>&1 | tail -20; docker logs "misp-nginx-$id" 2>&1 | tail -20; echo "FAIL: MISP did not start"; exit 1; fi
export OPENPICKET_TEST_MISP_URL="http://127.0.0.1:$port"
export OPENPICKET_TEST_MISP_KEY="$key"
COUNT=1 go test -count=1 ./test/ -run MISP -v
