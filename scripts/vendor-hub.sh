#!/usr/bin/env bash
# Pins the CrowdSec hub items OpenPicket's built-in content needs
# (hub/vendor): the manager stores them in PostgreSQL at start like the
# OpenPicket parsers and scenarios, so CrowdSec runs offline.
#
#   scripts/vendor-hub.sh            refresh the listed items
#
# Each file is checked against the index digest. After a change, bump
# hub.BuiltinRevision and update hub/builtin.sum (go test ./hub/ says how).
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${HUB_BASE:-https://cdn-hub.crowdsec.net/crowdsecurity/master}"
# type name
ITEMS=(
  "parsers crowdsecurity/syslog-logs"
  "parsers crowdsecurity/dateparse-enrich"
  "parsers crowdsecurity/whitelists"
)
out=hub/vendor
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsS -o "$work/index.json" "$BASE/.index.json"
rm -rf "$out"
mkdir -p "$out"
manifest="[]"
for it in "${ITEMS[@]}"; do
  read -r type name <<<"$it"
  entry="$(jq -c --arg t "$type" --arg n "$name" '.[$t][$n] // empty' "$work/index.json")"
  [ -n "$entry" ] || { echo "not in the hub index: $type $name" >&2; exit 1; }
  path="$(jq -r .path <<<"$entry")"
  version="$(jq -r .version <<<"$entry")"
  digest="$(jq -r --arg v "$version" '.versions[$v].digest' <<<"$entry")"
  if [ "$(jq -r '.data // [] | length' <<<"$entry")" != 0 ]; then
    echo "$type $name needs data files: not supported for built-in items" >&2
    exit 1
  fi
  mkdir -p "$out/$(dirname "$path")"
  curl -fsS -o "$out/$path" "$BASE/$path"
  got="$(sha256sum "$out/$path" | cut -d' ' -f1)"
  [ "$got" = "$digest" ] || { echo "$path: sha256 $got, index says $digest" >&2; exit 1; }
  manifest="$(jq -c --arg t "$type" --arg n "$name" --arg p "$path" --arg v "$version" --arg d "$digest" \
    --arg s "$(jq -r '.stage // ""' <<<"$entry")" '. + [{type: $t, name: $n, path: $p, version: $v, digest: $d, stage: $s}]' <<<"$manifest")"
  echo "$type $name $version"
done
jq . <<<"$manifest" >"$out/manifest.json"
