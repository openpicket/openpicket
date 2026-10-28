# openpicket-k8s-collector Helm chart

Installs openpicket-agent-k8s-collector: one Deployment (one replica) that
follows the containers of the configured pods through the Kubernetes API
and ships their lines to OpenPicket as one node. See
[docs/kubernetes.md](../../../docs/kubernetes.md).

```sh
helm install k8s-logs deploy/helm/openpicket-k8s-collector \
  -n openpicket-k8s-collector --create-namespace \
  --set openpicket.url=ws://openpicket-gateway.openpicket.svc:8080/agent/data/v1/connect \
  --set openpicket.hostKey="ssh-ed25519 AAAA... openpicket-manager" \
  -f targets.yaml
```

| Value | |
|---|---|
| `nodeId` | The node in OpenPicket (default `k8s-logs`). |
| `openpicket.url`, `openpicket.hostKey` | Required: the gateways' channel B endpoint and the manager's host key (**Nodes > Connection info**). |
| `openpicket.headers`, `openpicket.caCert`, `openpicket.tlsInsecureSkipVerify` | For an access proxy or a private CA. |
| `targets` | Required: the pods to follow (`namespace`, `selector`, `field_selector`, `workload`, `service_account`, `pod`, `containers`, `program`). |
| `key.existingSecret` / `key.privateKey` | Your own ed25519 key. Default: generated once, kept on upgrades and uninstall. |
| `state.enabled`, `state.persistence.*` | Positions on an emptyDir (default), a PVC, or none (stateless). |
| `rbac.clusterWide`, `rbac.extraNamespaces` | By default a RoleBinding in each target's namespace. |

After the install, register the public key printed by the command in the
release notes (`openpicket-agent-k8s-collector pubkey`) under
**Nodes > Register node**.
