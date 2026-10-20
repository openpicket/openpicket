# syntax=docker/dockerfile:1
# openpicket-suricontroller image: suricontroller with the shared node
# registry in PostgreSQL and the principal tokens of openpicket-manager.
# Build from the repository root:
#   docker build -f deploy/images/suricontroller/Dockerfile -t openpicket-suricontroller .

# suri-controller-web comes from the suricontroller module pinned in go.mod.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS ui-src
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download github.com/jc-lab/suricontroller \
 && cp -r "$(go list -m -f '{{.Dir}}' github.com/jc-lab/suricontroller)/web/ui" /ui \
 && chmod -R u+w /ui

FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /w/ui
COPY --from=ui-src /ui/package.json /ui/package-lock.json ./
RUN npm ci
COPY --from=ui-src /ui/ ./
# vite writes ../dist
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=web /w/dist/ ./internal/suriweb/dist/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/openpicket/openpicket/pkg/version.Version=${VERSION}" \
    -o /out/openpicket-suricontroller ./cmd/openpicket-suricontroller

# The binary that goes into the image. CI replaces this stage with its
# prebuilt binary (--build-context binary=<dir>).
FROM scratch AS binary
COPY --from=build /out/openpicket-suricontroller /openpicket-suricontroller

FROM alpine:3.24
# git: rule and configuration repositories.
RUN apk add --no-cache ca-certificates tzdata tini git && adduser -D -H -u 10001 openpicket \
 && mkdir -p /var/lib/openpicket-suricontroller && chown openpicket /var/lib/openpicket-suricontroller
COPY --from=binary /openpicket-suricontroller /usr/bin/openpicket-suricontroller
USER openpicket
ENV OPENPICKET_SURI_LISTEN=:8080 OPENPICKET_SURI_DATA_DIR=/var/lib/openpicket-suricontroller
VOLUME ["/var/lib/openpicket-suricontroller"]
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/openpicket-suricontroller"]
CMD ["serve"]
