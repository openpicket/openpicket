#!/usr/bin/env bash
# Builds an air-gapped installation bundle: every image of the chart
# (docker save), the packaged Helm chart, the agent image and a script
# that pushes the images to a private registry.
#
#   scripts/airgap-bundle.sh <version> [out.tar.gz]
#
# The images must exist locally as openpicket-<name>:<version> (make images
# VERSION=<version>); third-party images are pulled for the target
# platform (PLATFORM, default linux/amd64).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:?version}"
OUT="${2:-openpicket-airgap-${VERSION}.tar.gz}"
PLATFORM="${PLATFORM:-linux/amd64}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/images"

own=(openpicket-manager openpicket-suricontroller openpicket-crowdsec openpicket-agent)
third=(postgres:16-alpine grafana/loki:3.5.0)
for name in "${own[@]}"; do
  docker image inspect "$name:$VERSION" >/dev/null
  docker tag "$name:$VERSION" "ghcr.io/openpicket/$name:$VERSION"
  docker save "ghcr.io/openpicket/$name:$VERSION" | gzip > "$work/images/$name.tar.gz"
  echo "saved $name:$VERSION"
done
for img in "${third[@]}"; do
  docker pull --platform "$PLATFORM" "$img" >/dev/null
  docker save --platform "$PLATFORM" "$img" | gzip > "$work/images/$(echo "$img" | tr '/:' '__').tar.gz"
  echo "saved $img"
done

# The chart version must be semver; image versions may not be (git describe).
chart_version="$(sed -n 's/^version: //p' deploy/helm/openpicket/Chart.yaml)"
if [[ "${VERSION#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$ ]]; then chart_version="${VERSION#v}"; fi
helm package deploy/helm/openpicket --version "$chart_version" --app-version "$VERSION" -d "$work" >/dev/null
cp deploy/images/agent/agent.yaml.example deploy/images/agent/docker-compose.yml "$work/"
cat > "$work/push-images.sh" <<'PUSH'
#!/usr/bin/env bash
# Loads the images and pushes them to REGISTRY (e.g. registry.local:5000).
# Then install with: helm install openpicket openpicket-*.tgz --set global.imageRegistry=$REGISTRY
set -euo pipefail
REGISTRY="${1:?registry}"
cd "$(dirname "$0")/images"
for f in *.tar.gz; do
  ref="$(docker load < "$f" | sed -n 's/^Loaded image: //p' | head -1)"
  # ghcr.io/openpicket/x:v -> $REGISTRY/ghcr.io/openpicket/x:v ... keep the
  # repository path under the registry so global.imageRegistry applies.
  target="$REGISTRY/$ref"
  docker tag "$ref" "$target"
  docker push "$target"
done
PUSH
chmod +x "$work/push-images.sh"
cat > "$work/README.txt" <<README
OpenPicket ${VERSION} air-gapped bundle

1. ./push-images.sh registry.local:5000
2. helm install openpicket openpicket-*.tgz -n openpicket --create-namespace \\
     --set global.imageRegistry=registry.local:5000 \\
     --set suricontroller.disableETOpen=true --set publicURL=https://openpicket.example.com
3. Routers: load images/openpicket-agent.tar.gz with docker load, use
   docker-compose.yml and agent.yaml.example.
README
tar -C "$work" -czf "$OUT" .
echo "bundle: $OUT ($(du -h "$OUT" | cut -f1))"
