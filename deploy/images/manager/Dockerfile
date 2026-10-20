# syntax=docker/dockerfile:1
# openpicket-manager image (data plane endpoint, pipeline, API and web UI).
# Build from the repository root:
#   docker build -f deploy/images/manager/Dockerfile -t openpicket-manager .
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/web/ui
COPY web/ui/package.json web/ui/package-lock.json ./
RUN npm ci
COPY web/ui/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=web /src/web/dist/ ./web/dist/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/openpicket/openpicket/pkg/version.Version=${VERSION}" \
    -o /out/openpicket-manager ./cmd/openpicket-manager

# The binary that goes into the image. CI replaces this stage with its
# prebuilt binary (--build-context binary=<dir>).
FROM scratch AS binary
COPY --from=build /out/openpicket-manager /openpicket-manager

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata tini && adduser -D -H -u 10001 openpicket
COPY --from=binary /openpicket-manager /usr/bin/openpicket-manager
USER openpicket
ENV OPENPICKET_LISTEN=:8080 OPENPICKET_METRICS_LISTEN=:9090
EXPOSE 8080 9090
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/openpicket-manager"]
CMD ["serve"]
