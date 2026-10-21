#!/usr/bin/env bash
# Runs kernel-level tests (NFLOG reception, nftables enforcement) inside a
# throwaway container with CAP_NET_ADMIN, nftables and its own network
# namespace. Usage: scripts/netns-test.sh [package...]
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=openpicket-nftcheck:2
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'FROM alpine:3.22\nRUN apk add --no-cache nftables iproute2 netcat-openbsd\n' | docker build --network host -q -t "$IMAGE" - >/dev/null
fi
pkgs=("${@:-./agent/nflog/ ./agent/nft/ ./agent/enforcer/ ./agent/policy/}")
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
for p in ${pkgs[@]}; do
  [ -d "$p" ] || continue
  name="$(echo "$p" | tr '/.' '__')"
  CGO_ENABLED=0 go test -c -o "$out/$name.test" "$p"
done
status=0
for t in "$out"/*.test; do
  [ -e "$t" ] || continue
  echo "== $(basename "$t")"
  # --privileged: the packet tests create network namespaces.
  docker run --rm --privileged --network none -e OPENPICKET_TEST_NETNS=1 -e OPENPICKET_TEST_NFT=1 \
    -v "$t:/test:ro" "$IMAGE" /test -test.v -test.run 'Kernel|Netns|Packet' 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok|panic|\s+\S+_test.go)' || status=1
done
exit $status
