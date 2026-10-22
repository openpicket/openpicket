# OpenPicket

All-in-one, pluggable network security for routers and servers:
Suricata on the edge, CrowdSec for detection and decisions, nftables
enforcement on every node, and a central manager with a web UI.

| Component | Role |
|---|---|
| **openpicket-agent** | Edge (docker, OpenWrt or Linux). Runs Suricata through the embedded suricontroller agent, collects eve and NFLOG records, enforces CrowdSec decisions and port policies with nftables. |
| **openpicket-manager** | Data plane and UI (N replicas, state in PostgreSQL). Receives logs (at-least-once) and forwards them to Grafana Loki and CrowdSec, distributes decisions and port policies, serves the UI. |
| **openpicket-suricontroller** | Suricata control plane (1 replica): rules, configuration, bundles, deployment. [suricontroller](https://github.com/jc-lab/suricontroller) with its store in the shared PostgreSQL. |

Each agent keeps two outbound connections with one key: channel A to
openpicket-suricontroller (Suricata management) and channel B to the manager
(logs, status, decisions, policies). Both run Noise IK over WebSocket, so
TLS can terminate anywhere in between.

## Installation

- Management side: [Helm chart](deploy/helm/openpicket/README.md)
- Agent on OpenWrt: [docs/openwrt.md](docs/openwrt.md)

## Layout

| Path | Contents |
|---|---|
| `proto/` | Channel B protocol (`openpicket.dataplane.v1`) |
| `pkg/` | Shared packages: `dpwire` (channel B framing), `principal` (manager → suricontroller user token) |
| `internal/schema` | PostgreSQL schema and migrations (shared by all binaries) |
| `suristore/` | suricontroller `store.Store` on PostgreSQL (shared node registry) |
| `suriauth/` | suricontroller authentication through the manager |
| `manager/` | openpicket-manager |
| `agent/` | openpicket-agent |
| `cmd/` | Binaries |

## Development

OpenPicket uses suricontroller as a Go module, pinned in `go.mod` to a
commit of its `feat/openpicket-extensions` branch. `make suricata-web`
builds suricontroller's web UI from that module (it is embedded in
openpicket-suricontroller).

```sh
make build      # bin/openpicket-{manager,agent,suricontroller}
make test       # unit tests (Postgres tests are skipped)
make test-pg    # all tests with a throwaway PostgreSQL in docker
make lint
make proto      # regenerate gen/ (needs protoc)
```

## License

[Mozilla Public License 2.0](LICENSE)
