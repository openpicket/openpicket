package manager

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openpicket/openpicket/manager/gateway"
	"github.com/openpicket/openpicket/manager/registry"
)

// nodeCollector exports the latest status report of the nodes connected
// to this replica. Every node is connected to one replica at a time, so
// sums across replicas give the cluster view.
type nodeCollector struct {
	gw    *gateway.Gateway
	nodes *registry.Registry
}

var (
	nodeLabels         = []string{"node", "site"}
	descConnected      = prometheus.NewDesc("openpicket_node_connected", "1 for a node with a data plane session on this replica.", nodeLabels, nil)
	descQueueBytes     = prometheus.NewDesc("openpicket_node_log_queue_bytes", "Bytes waiting in the agent's log queue.", nodeLabels, nil)
	descQueueCap       = prometheus.NewDesc("openpicket_node_log_queue_capacity_bytes", "Capacity of the agent's log queue.", nodeLabels, nil)
	descDropped        = prometheus.NewDesc("openpicket_node_log_agent_dropped_records", "Records the agent dropped (queue full) since it started.", nodeLabels, nil)
	descSent           = prometheus.NewDesc("openpicket_node_log_sent_records", "Records the agent sent since it started.", nodeLabels, nil)
	descBans           = prometheus.NewDesc("openpicket_node_ban_elements", "Elements in the node's ban sets.", append(nodeLabels, "direction", "family"), nil)
	descRejected       = prometheus.NewDesc("openpicket_node_decisions_rejected", "Decisions refused by the node's local policy.", nodeLabels, nil)
	descDecisionsVer   = prometheus.NewDesc("openpicket_node_decisions_version", "Decision set version applied by the node.", nodeLabels, nil)
	descPolicyVer      = prometheus.NewDesc("openpicket_node_policy_version", "Port policy bundle version applied by the node.", nodeLabels, nil)
	descApplyError     = prometheus.NewDesc("openpicket_node_apply_error", "1 when the node reports an apply error.", append(nodeLabels, "what"), nil)
	descPolicyPackets  = prometheus.NewDesc("openpicket_node_policy_packets", "Packets matched per port policy rule.", append(nodeLabels, "rule"), nil)
	descNflogRecords   = prometheus.NewDesc("openpicket_node_nflog_records", "NFLOG records per prefix since the agent started.", append(nodeLabels, "prefix"), nil)
	nodeCollectorDescs = []*prometheus.Desc{descConnected, descQueueBytes, descQueueCap, descDropped, descSent, descBans, descRejected,
		descDecisionsVer, descPolicyVer, descApplyError, descPolicyPackets, descNflogRecords}
)

func (c *nodeCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range nodeCollectorDescs {
		ch <- d
	}
}

func (c *nodeCollector) Collect(ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	for _, s := range c.gw.Sessions() {
		node, site := s.NodeID, ""
		// Labels may change while connected: the registry has the current ones.
		if cur := c.nodes.Node(node); cur != nil {
			site = cur.Site()
		} else if s.Node != nil {
			site = s.Node.Site()
		}
		gauge(descConnected, 1, node, site)
		st := s.Status()
		if st == nil {
			continue
		}
		if l := st.GetLogs(); l != nil {
			gauge(descQueueBytes, float64(l.GetQueueBytes()), node, site)
			gauge(descQueueCap, float64(l.GetQueueCapacityBytes()), node, site)
			gauge(descDropped, float64(l.GetDroppedRecords()), node, site)
			gauge(descSent, float64(l.GetSentRecords()), node, site)
		}
		if e := st.GetEnforcer(); e.GetEnabled() {
			gauge(descBans, float64(e.GetBanInV4()), node, site, "inbound", "ipv4")
			gauge(descBans, float64(e.GetBanInV6()), node, site, "inbound", "ipv6")
			gauge(descBans, float64(e.GetBanBothV4()), node, site, "both", "ipv4")
			gauge(descBans, float64(e.GetBanBothV6()), node, site, "both", "ipv6")
			gauge(descRejected, float64(e.GetRejected()), node, site)
			gauge(descDecisionsVer, float64(e.GetDecisionsVersion()), node, site)
			gauge(descApplyError, b(e.GetLastError() != ""), node, site, "decisions")
		}
		if p := st.GetPolicy(); p.GetEnabled() {
			gauge(descPolicyVer, float64(p.GetVersion()), node, site)
			gauge(descApplyError, b(p.GetLastError() != ""), node, site, "policy")
			for rule, n := range p.GetPackets() {
				gauge(descPolicyPackets, float64(n), node, site, rule)
			}
		}
		if n := st.GetNflog(); n.GetEnabled() {
			gauge(descApplyError, b(n.GetLastError() != ""), node, site, "nflog")
			for prefix, v := range n.GetRecords() {
				gauge(descNflogRecords, float64(v), node, site, prefix)
			}
		}
	}
}
