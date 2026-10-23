# OpenPicket CrowdSec image (docs/ARCHITECTURE.md §8): CrowdSec without
# any hub content. Log processors get their parsers, scenarios and data
# files from openpicket-manager (openpicket-crowdsec-sync, port 8082) and
# start CrowdSec once they have them; nothing is downloaded at runtime.
#
# Build from the repository root:
#   docker build -f deploy/images/crowdsec/Dockerfile -t openpicket-crowdsec .
ARG CROWDSEC_VERSION=v1.8.1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/openpicket/openpicket/pkg/version.Version=${VERSION}" \
    -o /out/openpicket-crowdsec-sync ./cmd/openpicket-crowdsec-sync

# The binary that goes into the image. CI replaces this stage with its
# prebuilt binary (--build-context binary=<dir>).
FROM scratch AS binary
COPY --from=build /out/openpicket-crowdsec-sync /openpicket-crowdsec-sync

FROM crowdsecurity/crowdsec:${CROWDSEC_VERSION}

# The base image keeps its configuration in /staging and copies it to
# /etc/crowdsec on first start. Empty both of hub content.
RUN set -eux; \
    apk add --no-cache tini; \
    cp -a /staging/etc/crowdsec /etc/; \
    for d in /etc/crowdsec /staging/etc/crowdsec; do \
        rm -rf "$d"/parsers "$d"/postoverflows "$d"/scenarios "$d"/collections "$d"/contexts \
            "$d"/appsec-configs "$d"/appsec-rules "$d"/hub; \
        mkdir -p "$d"/parsers "$d"/postoverflows "$d"/scenarios "$d"/collections "$d"/contexts \
            "$d"/appsec-configs "$d"/appsec-rules "$d"/hub; \
        # CrowdSec needs an index to start; every item is local.
        echo '{}' > "$d"/hub/.index.json; \
    done; \
    # Pin the hub branch: without it cscli asks version.crowdsec.net for
    # the latest release, which fails offline.
    yq -i '.cscli.hub_branch = "master"' /etc/crowdsec/config.yaml; \
    cp /etc/crowdsec/config.yaml /staging/etc/crowdsec/config.yaml; \
    # Hub data files and GeoIP databases of the base image: data files
    # come with the content, geo with the records (the manager's MaxMind
    # databases).
    find /var/lib/crowdsec/data /staging/var/lib/crowdsec/data -mindepth 1 -maxdepth 1 ! -name 'crowdsec.db*' -exec rm -rf {} +; \
    # The stock entrypoint links /staging/var/lib/crowdsec/data/* into the
    # data directory: an empty one leaves a literal "*" link that fails
    # the next start.
    echo 'OpenPicket: data files come with the content (openpicket-crowdsec-sync).' > /staging/var/lib/crowdsec/data/README.openpicket; \
    # The stock entrypoint installs these on every start (from the hub):
    # content is the manager's business here.
    sed -i '/cscli_if_clean parsers install crowdsecurity\/\(docker\|cri\)-logs/d' /docker_start.sh; \
    ! grep -q 'parsers install crowdsecurity/docker-logs' /docker_start.sh

# Configuration, not content: the datasource receiving the manager's
# records, decision profiles and the alert context.
COPY hub/profiles.yaml /etc/crowdsec/profiles.yaml
COPY hub/console-context.yaml /etc/crowdsec/console/context.yaml
COPY hub/acquis.d/ /etc/crowdsec/acquis.d/

RUN set -eux; \
    echo '# Acquisition is in acquis.d (OpenPicket records over HTTP).' > /etc/crowdsec/acquis.yaml; \
    cp /etc/crowdsec/profiles.yaml /etc/crowdsec/acquis.yaml /staging/etc/crowdsec/; \
    mkdir -p /staging/etc/crowdsec/console /staging/etc/crowdsec/acquis.d; \
    cp /etc/crowdsec/console/context.yaml /staging/etc/crowdsec/console/; \
    cp /etc/crowdsec/acquis.d/* /staging/etc/crowdsec/acquis.d/

# No CAPI registration, no console; LAPIs share PostgreSQL (configured by
# the Helm chart), so the local database volume check does not apply.
ENV DISABLE_ONLINE_API=true \
    NO_HUB_UPGRADE=true \
    CROWDSEC_BYPASS_DB_VOLUME_CHECK=true

COPY deploy/images/crowdsec/start.sh /usr/local/bin/openpicket-crowdsec-start
COPY --from=binary /openpicket-crowdsec-sync /usr/local/bin/openpicket-crowdsec-sync
# Log processors: the sync process (port 8082) starts CrowdSec once it has
# content. LAPI-only containers (DISABLE_AGENT=true) run the start script.
EXPOSE 8082
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/openpicket-crowdsec-sync"]
