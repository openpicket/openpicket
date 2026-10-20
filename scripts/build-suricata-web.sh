#!/usr/bin/env bash
# Builds suri-controller-web (suricontroller's web UI) from the
# github.com/jc-lab/suricontroller module source pinned in go.mod into
# internal/suriweb/dist, where openpicket-suricontroller embeds it.
# Needs Go and Node.js (npm).
set -euo pipefail
cd "$(dirname "$0")/.."
mod=github.com/jc-lab/suricontroller
go mod download "$mod"
src="$(go list -m -f '{{.Dir}}' "$mod")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# The module cache is read-only; build in a copy (vite writes ../dist).
cp -r "$src/web/ui" "$work/ui"
chmod -R u+w "$work"
(cd "$work/ui" && npm ci --no-audit --no-fund && npm run build)
out=internal/suriweb/dist
find "$out" -mindepth 1 ! -name .keep -exec rm -rf {} +
cp -r "$work/dist/." "$out/"
touch "$out/.keep"
echo "built suri-controller-web ($(go list -m -f '{{.Version}}' "$mod")) into $out"
