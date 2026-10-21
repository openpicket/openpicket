#!/usr/bin/env bash
# Runs the OpenSearch sink integration test against a throwaway OpenSearch
# (security plugin disabled) and PostgreSQL.
set -euo pipefail
cd "$(dirname "$0")/.."
name="openpicket-os-test-$$"
docker run -d --rm --name "$name" -p 127.0.0.1::9200 -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e DISABLE_INSTALL_DEMO_CONFIG=true -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" "${IMAGE:-opensearchproject/opensearch:2.19.2}" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
port="$(docker port "$name" 9200/tcp | head -1 | sed 's/.*://')"
for _ in $(seq 1 120); do
  curl -fs "http://127.0.0.1:$port/_cluster/health" >/dev/null 2>&1 && break
  sleep 1
done
export OPENPICKET_TEST_OPENSEARCH_URL="http://127.0.0.1:$port"
COUNT=1 ./scripts/test-pg.sh ./test/ -run OpenSearch -v
