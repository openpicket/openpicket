#!/usr/bin/env bash
# Generates TypeScript code (protobuf-es v2 messages and service
# descriptors) for openpicket-web into web/ui/src/gen/. Requires protoc and
# `npm ci` in web/ui; the suricontroller protos the API imports come from
# the module pinned in go.mod. The output is committed so that
# `npm run build` does not need protoc.
set -euo pipefail
cd "$(dirname "$0")/.."

go mod download github.com/jc-lab/suricontroller
SURI="$(go list -m -f '{{.Dir}}' github.com/jc-lab/suricontroller)"
PLUGIN="$PWD/web/ui/node_modules/.bin/protoc-gen-es"
OUT="$PWD/web/ui/src/gen"
if [ ! -x "$PLUGIN" ]; then
  echo "protoc-gen-es not found; run 'npm ci' in web/ui first" >&2
  exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"
mapfile -t PROTOS < <(find proto -name '*.proto' | sort)
# Imported suricontroller protos (paths relative to $SURI/proto).
SURI_PROTOS=(suricontroller/agent/v1/agent.proto)
protoc -I proto -I "$SURI/proto" \
  --plugin=protoc-gen-es="$PLUGIN" \
  --es_out="$OUT" \
  --es_opt=target=ts,import_extension=none \
  "${PROTOS[@]}" "${SURI_PROTOS[@]}"
echo "generated TypeScript into ${OUT#"$PWD"/}"
