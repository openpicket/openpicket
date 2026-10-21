// Package direction decides, for a record seen on a node, which side is the
// remote party and who started the connection (docs/ARCHITECTURE.md §4.7).
//
// "Who is outside" and "who started" are separate questions: a C2 server's
// reply (to_client) has the server as packet source, yet the connection was
// started by the inside host, so it is outbound and the server is the
// remote.
package direction

import (
	"net/netip"
	"strings"
)

// Direction of a connection relative to the node.
const (
	Inbound  = "inbound"
	Outbound = "outbound"
	// Internal: both ends inside. No remote.
	Internal = "internal"
	// Transit: both ends outside (routed through the node).
	Transit = "transit"
)

// Confidence of the initiator judgement.
const (
	High = "high"
	// Low: no flow information and no direction field; the packet source
	// was assumed to be the initiator.
	Low = "low"
)

// Nets is the set of networks a node considers inside.
type Nets struct {
	prefixes []netip.Prefix
}

// NewNets parses CIDRs and addresses; invalid entries are skipped and
// returned.
func NewNets(items ...[]string) (*Nets, []string) {
	n := &Nets{}
	var bad []string
	for _, list := range items {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if p, err := netip.ParsePrefix(s); err == nil {
				n.prefixes = append(n.prefixes, p.Masked())
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				a = a.Unmap()
				n.prefixes = append(n.prefixes, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			bad = append(bad, s)
		}
	}
	return n, bad
}

// Contains reports whether ip (a textual address) is inside.
func (n *Nets) Contains(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return n.ContainsAddr(a)
}

// ContainsAddr reports whether a is inside.
func (n *Nets) ContainsAddr(a netip.Addr) bool {
	if n == nil {
		return false
	}
	a = a.Unmap()
	for _, p := range n.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Prefixes returns the parsed networks.
func (n *Nets) Prefixes() []netip.Prefix {
	if n == nil {
		return nil
	}
	return append([]netip.Prefix(nil), n.prefixes...)
}

// Packet is what a record tells about one packet and its flow.
type Packet struct {
	SrcIP, DestIP string
	// FlowSrcIP is the flow's client side (eve alert "flow.src_ip"), if
	// known.
	FlowSrcIP string
	// PacketDirection is the eve "direction" field: "to_server" or
	// "to_client", if known.
	PacketDirection string
	// SrcIsInitiator marks records whose source always started the
	// connection (nflog of new inbound connections).
	SrcIsInitiator bool
}

// Result of a judgement.
type Result struct {
	Direction  string
	Confidence string
	// RemoteIP is empty for internal traffic.
	RemoteIP string
	// LocalIP is empty for transit traffic.
	LocalIP string
}

// initiator returns the address that started the connection.
func initiator(p Packet) (string, string) {
	switch {
	case p.SrcIsInitiator:
		return p.SrcIP, High
	case p.FlowSrcIP != "":
		return p.FlowSrcIP, High
	case p.PacketDirection == "to_server":
		return p.SrcIP, High
	case p.PacketDirection == "to_client":
		return p.DestIP, High
	default:
		return p.SrcIP, Low
	}
}

// Judge classifies p against the node's inside networks.
func Judge(n *Nets, p Packet) Result {
	srcIn, dstIn := n.Contains(p.SrcIP), n.Contains(p.DestIP)
	init, conf := initiator(p)
	switch {
	case srcIn && dstIn:
		return Result{Direction: Internal, Confidence: conf}
	case !srcIn && !dstIn:
		return Result{Direction: Transit, Confidence: conf, RemoteIP: init}
	}
	r := Result{Confidence: conf}
	if srcIn {
		r.LocalIP, r.RemoteIP = p.SrcIP, p.DestIP
	} else {
		r.LocalIP, r.RemoteIP = p.DestIP, p.SrcIP
	}
	if init == r.LocalIP {
		r.Direction = Outbound
	} else {
		r.Direction = Inbound
	}
	return r
}
