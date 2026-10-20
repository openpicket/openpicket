VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/openpicket/openpicket/pkg/version.Version=$(VERSION)
GO      ?= go

.PHONY: all build manager agent suricontroller proto test test-pg lint web suricata-web clean

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

test:
	$(GO) test -race ./...

# Runs the Postgres-backed tests against a throwaway container.
test-pg:
	./scripts/test-pg.sh

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
