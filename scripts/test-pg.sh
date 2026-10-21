#!/usr/bin/env bash
# Runs the Go tests with a throwaway PostgreSQL (docker). Tests that need
# Postgres read OPENPICKET_TEST_PG and are skipped without it.
set -euo pipefail
cd "$(dirname "$0")/.."

name="openpicket-test-pg-$$"
docker run -d --rm --name "$name" -e POSTGRES_PASSWORD=test -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
trap 'docker rm -f "$name" >/dev/null' EXIT
# The image restarts the server once after initdb; wait for the second start.
for _ in $(seq 1 120); do
  if [ "$(docker logs "$name" 2>&1 | grep -c 'ready to accept connections')" -ge 2 ]; then break; fi
  sleep 0.5
done
port="$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')"
export OPENPICKET_TEST_NFT=1
export OPENPICKET_TEST_PG="postgres://postgres:test@127.0.0.1:${port}/postgres?sslmode=disable"
go test -race -count="${COUNT:-1}" "${@:-./...}"
