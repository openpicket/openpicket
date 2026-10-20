# syntax=docker/dockerfile:1
# openpicket-agent image: Suricata (>= 8.0) + openpicket-agent (the
# suricontroller node agent plus log shipping, NFLOG, bans and port
# policies). Runs with the host network on the router (docker-compose.yml).
# Build from the repository root:
#   docker build -f deploy/images/agent/Dockerfile -t openpicket-agent .
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/openpicket/openpicket/pkg/version.Version=${VERSION}" \
    -o /out/openpicket-agent ./cmd/openpicket-agent

# The binary that goes into the image. CI replaces this stage with its
# prebuilt binary (--build-context binary=<dir>).
FROM scratch AS binary
COPY --from=build /out/openpicket-agent /openpicket-agent

FROM alpine:3.24
# Exact apk version of Suricata (e.g. 8.0.7-r0); empty installs the current one.
ARG SURICATA_VERSION=
RUN apk add --no-cache suricata${SURICATA_VERSION:+=$SURICATA_VERSION} tini nftables ca-certificates tzdata \
 && suricata -V \
 && mkdir -p /usr/share/openpicket-agent/suricata /etc/suri-agent /var/lib/suri-agent /var/log/suricata \
 && cp -a /etc/suricata/. /usr/share/openpicket-agent/suricata/ \
 && mkdir -p /etc/suricata/rules.local
COPY --from=binary /openpicket-agent /usr/bin/openpicket-agent
COPY deploy/images/agent/agent.yaml.example /usr/share/openpicket-agent/agent.yaml.example
COPY deploy/images/agent/entrypoint.sh /usr/bin/openpicket-agent-entrypoint
VOLUME ["/etc/suri-agent", "/etc/suricata", "/var/lib/suri-agent", "/var/log/suricata"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/openpicket-agent-entrypoint"]
CMD ["run"]
