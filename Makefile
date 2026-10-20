VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/openpicket/openpicket/pkg/version.Version=$(VERSION)
GO      ?= go

.PHONY: all build manager agent suricontroller proto test test-pg test-netns test-crowdsec test-lapi image-crowdsec lint web suricata-web clean

all: build

build: manager agent suricontroller

manager:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-manager ./cmd/openpicket-manager

agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-agent ./cmd/openpicket-agent

suricontroller:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-suricontroller ./cmd/openpicket-suricontroller

# Regenerates code from proto/ (needs protoc).
proto:
	./scripts/gen-proto.sh
	./scripts/gen-proto-ts.sh

test:
	$(GO) test -race ./...

# Runs the Postgres-backed tests against a throwaway container.
test-pg:
	./scripts/test-pg.sh

# Kernel-level tests (NFLOG, nftables) in a container with CAP_NET_ADMIN.
test-netns:
	./scripts/netns-test.sh

image-crowdsec:
	docker build -f deploy/images/crowdsec/Dockerfile -t openpicket-crowdsec:dev .

# The CrowdSec image detects and decides offline (docker --network none).
test-crowdsec: image-crowdsec
	./scripts/crowdsec-image-test.sh openpicket-crowdsec:dev

# Watcher, alert copy and bouncer stream against a real LAPI.
test-lapi: image-crowdsec
	./scripts/lapi-test.sh

lint:
	golangci-lint run ./...

web:
	cd web/ui && npm ci && npm run build

# suricontroller's web UI (embedded in openpicket-suricontroller), built from
# the suricontroller module pinned in go.mod.
suricata-web:
	./scripts/build-suricata-web.sh

clean:
	rm -rf bin
