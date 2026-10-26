# syntax=docker/dockerfile:1
# openpicket-agent-k8s-collector image: ships the logs of Kubernetes pods
# to OpenPicket (deploy/k8s-collector, docs/kubernetes.md).
# Build from the repository root:
#   docker build -f deploy/images/k8s-collector/Dockerfile -t openpicket-agent-k8s-collector .
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/openpicket/openpicket/pkg/version.Version=${VERSION}" \
    -o /out/openpicket-agent-k8s-collector ./cmd/openpicket-agent-k8s-collector

# The binary that goes into the image. CI replaces this stage with its
# prebuilt binary (--build-context binary=<dir>).
FROM scratch AS binary
COPY --from=build /out/openpicket-agent-k8s-collector /openpicket-agent-k8s-collector

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata tini && adduser -D -H -u 10001 openpicket
COPY --from=binary /openpicket-agent-k8s-collector /usr/bin/openpicket-agent-k8s-collector
USER openpicket
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/openpicket-agent-k8s-collector"]
CMD ["run"]
