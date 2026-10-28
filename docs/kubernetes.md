# Shipping Kubernetes pod logs

`openpicket-agent-k8s-collector` sends the logs of selected pods to OpenPicket. It follows their containers through the Kubernetes API, as `kubectl logs -f` does, and ships the lines over channel B like openpicket-agent's log sources. CrowdSec reads them with the parsers of the **CrowdSec content** page (nginx, PostgreSQL, your own), and its bans reach the routers like any other decision.

It is one node in OpenPicket: one key, one Deployment with a single replica.

## Configuration

The Helm chart `deploy/helm/openpicket-k8s-collector` writes the configuration file from its values:

```yaml
nodeId: k8s-logs
openpicket:
  url: ws://openpicket-gateway.openpicket.svc:8080/agent/data/v1/connect
  hostKey: "ssh-ed25519 AAAA... openpicket-manager"
targets:
  - namespace: ingress-nginx
    workload: deployment/ingress-nginx-controller
    containers: [controller]
    program: nginx
  - namespace: web
    service_account: api                 # program: the container name
  - namespace: db
    selector: app.kubernetes.io/name=postgresql
    program: postgres
```

`openpicket.url` is the gateways' channel B endpoint: in the manager's cluster its Service, elsewhere the public `wss://` URL (`openpicket.caCert`, `openpicket.headers` for a private CA or an access proxy). **Nodes > Connection info** shows the host key.

A target takes the running pods of a namespace. Its selections combine (all must match); with none it takes every pod of the namespace.

| Field | Selects |
|---|---|
| `selector` | a label selector (`app=web,tier in (front,api)`) |
| `field_selector` | a field selector (`spec.nodeName=node-1`) |
| `workload` | the pods of a workload's selector: `deployment/<name>`, `statefulset/<name>`, `daemonset/<name>`, `replicaset/<name>` (`matchExpressions` included) |
| `service_account` | the pods running as this ServiceAccount |
| `pod` | one pod by name |
| `containers` | only these containers (default: all) |

`program` names the lines' program, which selects the CrowdSec parser (`nginx`, `postgres`; `syslog` for lines in syslog format, whose lines name their program). Without it, the container name is the program. A container taken by several targets is read once, under the first target.

The **CrowdSec content** page lists the programs received (**Log programs**) with the parsers that select them; install the matching collection (e.g. `crowdsecurity/nginx`).

The collector reaches the API with its pod's ServiceAccount. Run outside a cluster (tests), its configuration file takes `kubernetes: {api_url: https://..., token_file: ..., ca_file: ...}`.

## Positions and restarts

The collector asks for each line's timestamp. After the manager acknowledged a line, its timestamp is the container's position. A stream that ends (container restart, kubelet log rotation) resumes after its last line without repeating it.

| Values | After a restart of the collector |
|---|---|
| `state.persistence.enabled=true` (a PVC) | each container resumes after its last acknowledged line; pods that started meanwhile are read from the last save |
| default (an emptyDir) | the same after a container restart; a new pod starts at the containers' current ends |
| `state.enabled=false` | stateless: every restart starts at the containers' current ends |

The first start (no state) begins at the containers' current ends: their backlog is not sent. Pods that appear later are read from their start. Lines are delivered at least once: lines read but not acknowledged before a restart are sent again (their record ids are stable: `<pod uid>/<container>@<timestamp>#<n>`).

## Install

```sh
helm install k8s-logs deploy/helm/openpicket-k8s-collector \
  -n openpicket-k8s-collector --create-namespace -f values.yaml
```

1. The chart generates the node key (secret `<release>-openpicket-k8s-collector-key`, kept on uninstall and upgrades). Print its public key and register it under **Nodes > Register node**; its comment is the node id:

   ```sh
   kubectl -n openpicket-k8s-collector exec deploy/k8s-logs-openpicket-k8s-collector -- \
     openpicket-agent-k8s-collector pubkey -config /etc/openpicket-agent-k8s-collector/config.yaml
   ```

   Until then the collector retries its connection. To bring your own key instead (`openpicket-agent-k8s-collector keygen` or `ssh-keygen -t ed25519`): `key.existingSecret`, or `key.privateKey`.
2. Check:

   ```sh
   kubectl -n openpicket-k8s-collector exec deploy/k8s-logs-openpicket-k8s-collector -- \
     openpicket-agent-k8s-collector check -config /etc/openpicket-agent-k8s-collector/config.yaml
   ```

   `check` lists the containers each target takes now, and tests the state file, the key and the manager connection. The node page shows each target with its followed containers and line counts, under the **Kubernetes** feature.

## Permissions

The ClusterRole lists pods, reads their logs and reads the workloads' selectors. The chart grants it with a RoleBinding in each target's namespace only (`rbac.extraNamespaces` adds more; `rbac.clusterWide=true` grants it everywhere). Logs may hold tokens and personal data: bind only what you ship. The container runs as a non-root user with a read-only root filesystem and no capabilities.

## Limits

- Each followed container is one log stream through the API server to the kubelet. For hundreds of pods, or every pod of a node, a DaemonSet reading `/var/log/pods` scales better.
- Lines are shipped as the containers wrote them; the pod is not part of the line. Loki labels them with the node and the program.
- Init containers are not followed.
