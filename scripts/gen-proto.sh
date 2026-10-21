#!/usr/bin/env bash
# Generates Go code from proto/ into gen/. Requires protoc in PATH; the
# imported suricontroller protos come from the module pinned in go.mod.
set -euo pipefail
cd "$(dirname "$0")/.."

go mod download github.com/jc-lab/suricontroller
SURI="$(go list -m -f '{{.Dir}}' github.com/jc-lab/suricontroller)"
BIN="$PWD/bin"
mkdir -p "$BIN"
(cd tools && go build -o "$BIN/" google.golang.org/protobuf/cmd/protoc-gen-go connectrpc.com/connect/cmd/protoc-gen-connect-go)

rm -rf gen
mkdir -p gen
mapfile -t PROTOS < <(find proto -name '*.proto' | sort)
protoc -I proto -I "$SURI/proto" \
  --plugin=protoc-gen-go="$BIN/protoc-gen-go" \
  --plugin=protoc-gen-connect-go="$BIN/protoc-gen-connect-go" \
  --go_out=gen --go_opt=module=github.com/openpicket/openpicket/gen \
  --connect-go_out=gen --connect-go_opt=module=github.com/openpicket/openpicket/gen \
  "${PROTOS[@]}"
