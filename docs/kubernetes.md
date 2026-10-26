# Shipping Kubernetes pod logs

`openpicket-agent-k8s-collector` sends the logs of selected pods to OpenPicket. It follows their containers through the Kubernetes API, as `kubectl logs -f` does, and ships the lines over channel B like openpicket-agent's log sources. CrowdSec reads them with the parsers of the **CrowdSec content** page (nginx, PostgreSQL, your own), and its bans reach the routers like any other decision.

It is one node in OpenPicket: one key, one Deployment with a single replica.

## Configuration

```yaml
node_id: k8s-logs
key_file: /etc/openpicket-agent-k8s-collector/key/agent_ed25519
state_file: /var/lib/openpicket-agent-k8s-collector/positions.json   # optional
openpicket:
  url: ws://openpicket-gateway.openpicket.svc:8080/agent/data/v1/connect
  host_key: "ssh-ed25519 AAAA... openpicket-manager"
scan_interval: 10s
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

`kubernetes` reaches the API; by default the pod's ServiceAccount (in-cluster). For a test outside a cluster: `kubernetes: {api_url: https://..., token_file: ..., ca_file: ...}`.

## Positions and restarts

The collector asks for each line's timestamp. After the manager acknowledged a line, its timestamp is the container's position. A stream that ends (container restart, kubelet log rotation) resumes after its last line without repeating it.

| `state_file` | After a restart of the collector |
|---|---|
| on a PVC (`components/persistent-state`) | each container resumes after its last acknowledged line; pods that started meanwhile are read from the last save |
| on the default emptyDir | the same after a container restart; a new pod starts at the containers' current ends |
| unset | stateless: every restart starts at the containers' current ends |

The first start (no state) begins at the containers' current ends: their backlog is not sent. Pods that appear later are read from their start. Lines are delivered at least once: lines read but not acknowledged before a restart are sent again (their record ids are stable: `<pod uid>/<container>@<timestamp>#<n>`).

## Install

The manifests are in `deploy/k8s-collector` (kustomize).

1. Create the key and register it under **Nodes > Register node**. The comment of the public key is the node id:

   ```sh
   docker run --rm -v "$PWD:/out" ghcr.io/openpicket/openpicket-agent-k8s-collector \
     keygen -node-id k8s-logs -key-file /out/agent_ed25519
   # or: ssh-keygen -t ed25519 -N '' -C k8s-logs -f agent_ed25519
   kubectl create namespace openpicket-k8s-collector
   kubectl -n openpicket-k8s-collector create secret generic k8s-collector-key --from-file=agent_ed25519
   ```

2. Edit `config.yaml` (URL, host key from **Nodes > Connection info**, targets) and `rbac.yaml` (one RoleBinding per namespace of the targets).
3. For positions on a PVC, enable `components/persistent-state` in `kustomization.yaml`.
4. Apply and check:

   ```sh
   kubectl apply -k deploy/k8s-collector
   kubectl -n openpicket-k8s-collector exec deploy/k8s-collector -- \
     openpicket-agent-k8s-collector check -config /etc/openpicket-agent-k8s-collector/config.yaml
   ```

   `check` lists the containers each target takes now, and tests the state file, the key and the manager connection. The node page shows each target with its followed containers and line counts, under the **Kubernetes** feature.

## Permissions

The ClusterRole lists pods, reads their logs and reads the workloads' selectors; RoleBindings grant it in the target namespaces only. Logs may hold tokens and personal data: bind only what you ship. The container runs as a non-root user with a read-only root filesystem and no capabilities.

## Limits

- Each followed container is one log stream through the API server to the kubelet. For hundreds of pods, or every pod of a node, a DaemonSet reading `/var/log/pods` scales better.
- Lines are shipped as the containers wrote them; the pod is not part of the line. Loki labels them with the node and the program.
- Init containers are not followed.
