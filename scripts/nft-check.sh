#!/usr/bin/env bash
# Checks an nft script (stdin) against a real kernel: nft -c in a throwaway
# container with CAP_NET_ADMIN in its own network namespace.
set -euo pipefail
IMAGE=openpicket-nftcheck:1
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'FROM alpine:3.22\nRUN apk add --no-cache nftables\n' | docker build --network host -q -t "$IMAGE" - >/dev/null
fi
exec docker run --rm -i --cap-add NET_ADMIN --network none "$IMAGE" nft -c -f -
