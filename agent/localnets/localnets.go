// Package localnets computes what a node considers inside (§4.7): Suricata
// HOME_NET of the running instances, the host's interface addresses and the
// configured extra networks.
package localnets

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/agent/collector"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
)

func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// HomeNet returns the positive entries of vars.address-groups.HOME_NET,
// resolving $VAR references to other address groups. Groups nest
// ("[[192.168.0.0/16,!192.168.1.5],203.0.113.10]", as suricontroller
// renders the interface addresses in). Negations ("!x", "![...]") are
// ignored: they only narrow the set.
func HomeNet(effective *yaml.Node) []string {
	groups := child(child(effective, "vars"), "address-groups")
	var out []string
	var resolve func(name string, depth int)
	resolve = func(name string, depth int) {
		v := child(groups, name)
		if v == nil || v.Kind != yaml.ScalarNode || depth > 8 {
			return
		}
		for _, item := range positiveItems(v.Value) {
			switch {
			case item == "any":
			case strings.HasPrefix(item, "$"):
				resolve(strings.TrimPrefix(item, "$"), depth+1)
			default:
				out = append(out, item)
			}
		}
	}
	resolve("HOME_NET", 0)
	return out
}

// positiveItems splits a Suricata address value into its entries, leaving
// out negated ones and everything inside a negated group.
func positiveItems(s string) []string {
	var (
		out     []string
		item    strings.Builder
		negated []bool // per open group
		neg     bool   // the current entry or group is negated
	)
	inNegated := func() bool { return slices.Contains(negated, true) }
	flush := func() {
		if v := strings.TrimSpace(item.String()); v != "" && !neg && !inNegated() {
			out = append(out, v)
		}
		item.Reset()
		neg = false
	}
	for _, c := range s {
		switch c {
		case '[':
			negated = append(negated, neg)
			neg = false
		case ']':
			flush()
			if len(negated) > 0 {
				negated = negated[:len(negated)-1]
			}
		case ',':
			flush()
		case '!':
			neg = true
		case ' ', '\t':
		default:
			item.WriteRune(c)
		}
	}
	flush()
	return out
}

// Collect returns the local networks of the node.
func Collect(instances []collector.Instance, wan, extra []string) *dataplanev1.LocalNets {
	ln := &dataplanev1.LocalNets{Extra: slices.Clone(extra)}
	seen := map[string]bool{}
	for _, in := range instances {
		for _, n := range HomeNet(in.Effective) {
			if !seen[n] {
				seen[n] = true
				ln.HomeNet = append(ln.HomeNet, n)
			}
		}
	}
	ln.InterfaceAddrs = interfaceAddrs()
	return ln
}

// interfaceAddrs lists every host address (as /32 or /128): the WAN
// address must count as inside (outbound traffic captured after SNAT), but
// not the whole WAN subnet.
func interfaceAddrs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			addr := p.Addr().Unmap()
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
		}
	}
	slices.Sort(out)
	return out
}

// Nets builds the matcher of a LocalNets.
func Nets(ln *dataplanev1.LocalNets) *direction.Nets {
	n, _ := direction.NewNets(ln.GetHomeNet(), ln.GetInterfaceAddrs(), ln.GetExtra())
	return n
}

// UncoveredIPv6 returns LAN-side global IPv6 prefixes not covered by the
// local networks: without them, the node's own IPv6 hosts look external
// (§4.7). wan lists the WAN interfaces to skip.
func UncoveredIPv6(nets *direction.Nets, wan []string) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifs {
		if slices.Contains(wan, ifc.Name) || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is6() || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() {
				continue
			}
			if !nets.ContainsAddr(p.Masked().Addr()) {
				out = append(out, ifc.Name+" "+p.Masked().String())
			}
		}
	}
	return out
}
