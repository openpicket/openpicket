VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/openpicket/openpicket/pkg/version.Version=$(VERSION)
GO      ?= go

.PHONY: images image-manager image-suricontroller image-agent image-k8s-collector all build manager agent k8s-collector suricontroller proto test test-pg test-netns test-crowdsec test-lapi image-crowdsec lint web suricata-web clean

all: build

build: manager agent k8s-collector suricontroller

manager:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-manager ./cmd/openpicket-manager

agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-agent ./cmd/openpicket-agent

k8s-collector:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/openpicket-agent-k8s-collector ./cmd/openpicket-agent-k8s-collector

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

# Images (built from this repository).
VERSION ?= dev
# e.g. --network host where the build network has no DNS
DOCKER_BUILD_FLAGS ?=
images: image-manager image-suricontroller image-agent image-k8s-collector image-crowdsec

image-manager:
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/images/manager/Dockerfile --build-arg VERSION=$(VERSION) -t openpicket-manager:$(VERSION) .

image-suricontroller:
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/images/suricontroller/Dockerfile --build-arg VERSION=$(VERSION) -t openpicket-suricontroller:$(VERSION) .

image-agent:
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/images/agent/Dockerfile --build-arg VERSION=$(VERSION) -t openpicket-agent:$(VERSION) .

image-k8s-collector:
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/images/k8s-collector/Dockerfile --build-arg VERSION=$(VERSION) -t openpicket-agent-k8s-collector:$(VERSION) .

# OpenSearch sink against a real OpenSearch.
test-opensearch:
	./scripts/opensearch-test.sh

# MISP client against a real MISP (several minutes to start).
test-misp:
	./scripts/misp-test.sh

helm-lint:
	helm lint deploy/helm/openpicket
	helm template t deploy/helm/openpicket --set ingress.enabled=true --set networkPolicy.enabled=true \
	  --set monitoring.serviceMonitor.enabled=true --set monitoring.prometheusRule.enabled=true \
	  --set monitoring.grafanaDashboards.enabled=true --set misp.enabled=true >/dev/null

airgap:
	./scripts/airgap-bundle.sh $(VERSION)
