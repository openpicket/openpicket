# OpenPicket Helm chart

Installs the management side of OpenPicket:

| Component | Kind | Notes |
|---|---|---|
| openpicket-manager | Deployment (2+) | UI, API, decision relay, alert sync, notifications, CrowdSec content, policy compilation. Every replica is equal. |
| openpicket-gateway | Deployment (2+) | The agents' data plane, log pipeline, decision and policy distribution, syslog receiver (same image, `OPENPICKET_ROLE=gateway`). Optional: `gateway.enabled=false` lets the manager serve the agents. |
| openpicket-suricontroller | StatefulSet (1) | Suricata management, proxied at `/suricata/`. |
| CrowdSec LAPI | Deployment (2) | Shares PostgreSQL. Registers the agents' machine, the manager's watcher and bouncer keys. |
| CrowdSec agents | Deployment (2+) | Receive the manager's records (HTTP datasource, token-protected). |
| PostgreSQL | StatefulSet (1), optional | Use `database.external` with an HA server in production. |
| Loki | StatefulSet (1), optional | Single binary; use `loki.external` at scale. |

Every image works offline (no hub or CAPI downloads at runtime).

```sh
helm install openpicket deploy/helm/openpicket -n openpicket --create-namespace \
  --set publicURL=https://openpicket.example.com \
  --set ingress.enabled=true --set ingress.host=openpicket.example.com
```

The admin password, the channel B host key, the manager's key secret and
the CrowdSec credentials are generated once and kept in the
`<release>-openpicket-secrets` secret (it is kept on uninstall: agents pin
the host key).

## Gateways

What faces the agents runs apart from the UI and API (`gateway.enabled`,
on by default). The gateways hold the channel B host key but no login,
LAPI, hub or MISP credentials; the manager pods hold the key secret the
login sessions and suricontroller tokens derive from, not the host key.

The gateways connect to the database with their own role
(`gateway.database.user`, default `openpicket_gateway`): it reads what
they serve (nodes, decisions, policies, settings) and writes only
sessions, acknowledgements, watermarks and log counts. The manager creates
the role (or sets its password) and grants it on every start. The built-in
PostgreSQL allows that; on an external server the manager's account needs
`CREATEROLE`, or create the role beforehand:

```sql
CREATE ROLE openpicket_gateway LOGIN PASSWORD '...';
```

and give the same password in `gateway.database.password` or
`gateway.database.existingSecret`. With `gateway.database.user=""` the
gateways use the manager's account; the System page then warns that the
privileges are not separated.

Upgrading from a chart without gateways signs everyone out once (the login
keys move from the host key to the key secret); suricontroller restarts
with the new principal key on its own.

## Ingress

One host serves everything: `/agent/v1/connect` goes to openpicket-suricontroller
(agents' channel A), `/agent/data/v1/connect` to the gateways, every other
path to openpicket-manager (UI, API, `/suricata/` proxy). Agents keep
WebSocket connections open: raise the proxy read timeout of the ingress
controller.

With `ingress.ui.enabled` the UI and API get their own host (and ingress
class, e.g. an internal one): the main ingress then carries the agents'
paths only.

Agents only need the manager's URL and host key: the manager hands them the
channel A endpoint (`/agent/v1/connect` on the same host, and the
suricontroller host key). When agents reach suricontroller through another
host, set `manager.agentControllerURL`.

## Syslog (optional)

`syslog.enabled` lets devices without an agent (switches, firewalls, NAS)
send syslog to the gateways: UDP and TCP 514 (newline or octet-counting
framing) and, with `syslog.tls.enabled` and a certificate secret, TLS
6514. A LoadBalancer Service (`<release>-openpicket-syslog`) exposes them
with `externalTrafficPolicy: Local`: the device is recognized by the
sender's address, which must reach the pods unchanged.

Register devices on the **Syslog devices** page (address or network,
labels, program names for the CrowdSec parsers). `syslog.unregistered`
decides what happens to other senders until an admin changes it there:
`drop` counts them per address, `accept` takes them in as a temporary
device named after the address. Their lines go to CrowdSec and Loki like
the agents' generic logs, and alerts ban addresses as usual: UDP senders
can be spoofed, so expose syslog on internal networks only
(`syslog.service.loadBalancerSourceRanges`).

## Network policies

`networkPolicy.enabled` limits the CrowdSec datasource to the gateways, the
content sync to the manager and the database to OpenPicket's pods, and the
gateways' egress to DNS, the CrowdSec agents, the built-in Loki and
PostgreSQL. External targets of the gateways (database, Loki, OpenSearch)
need rules in `networkPolicy.gatewayEgress`.

## Authentication

`manager.auth.config` holds the provider chain (header, jwt, forward) and the
role mapping; `manager.auth.admin` the fixed bootstrap login. See
`manager/auth/config.go` for every option.

## Monitoring

`monitoring.serviceMonitor`, `monitoring.prometheusRule` and
`monitoring.grafanaDashboards` (ConfigMaps for the Grafana sidecar) need the
Prometheus Operator and Grafana. Dashboards are generated by
`scripts/gen-dashboards.py`.

## Storage

Every PVC (PostgreSQL, Loki, suricontroller, MISP and its MariaDB) uses its
`persistence.storageClass`, else `global.defaultStorageClass`, else the
cluster default. `-` sets `storageClassName: ""` (pre-provisioned volumes).

The built-in Loki keeps records for `loki.builtin.retention`. Generic logs
can be kept for another period by program
(`loki.builtin.programRetention: {nginx: 168h}`; syslog lines go by the
program of their header, `sshd`, `postfix/smtpd`), other streams with
`loki.builtin.retentionStreams` (Loki `retention_stream` entries). The
**CrowdSec content** page can also keep a program out of Loki entirely.

## Database connections

`database.maxConnections` caps the pool of each pod (manager 6, gateway 6,
suricontroller 4, CrowdSec LAPI 10). Each manager replica also keeps two
dedicated connections (LISTEN, one for all leader locks), each gateway
replica one (LISTEN). With the defaults the chart opens at most
2 x (6 + 2) + 2 x (6 + 1) + 4 + 2 x 10 = 54. Behind pgpool, keep
`num_init_children` above that (plus other clients), and
`num_init_children x max_pool` within PostgreSQL `max_connections`.

## Air-gapped installation

`scripts/airgap-bundle.sh <version>` saves every image and the packaged chart;
the bundle's `push-images.sh` loads them into a private registry, used with
`global.imageRegistry`. Set `suricontroller.disableETOpen=true`.

## OpenSearch (optional)

`opensearch.enabled` with `opensearch.url` sends every record, after the
acknowledgement and best effort, to data streams `openpicket-eve-<event_type>`,
`openpicket-nflog` and `openpicket-<type>`, plus the LAPI alerts to
`openpicket-crowdsec-alerts`. The record id is the document id, so
retransmissions never duplicate. The manager applies the index template and
an ISM retention policy (`opensearch.retention`).

## MISP (optional)

`misp.enabled` turns on the approval queue (docs: `deploy/misp/README.md`).
With `misp.external.url` and its API key the manager uses an existing MISP
(install the `openpicket` taxonomy there). Without it the chart deploys MISP
(misp-core, MariaDB, Valkey) with the taxonomy mounted, an API key generated
for the manager, and offline defaults (no feed pull/push).
