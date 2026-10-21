package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// PolicyTable holds the port policies; it is replaced as a whole when the
// bundle changes (docs/ARCHITECTURE.md §4.4).
const PolicyTable = "openpicket_policy"

// PolicyConfig is the agent-owned part of the policy table: which
// interfaces, the allowlist, and the logging rate. Nothing here comes from
// the manager.
type PolicyConfig struct {
	// WAN is read when the table is rendered; the table is rendered again
	// when it changes.
	WAN *WAN
	// LogRate limits POLICY-DROP logging per rule ("30/minute").
	LogRate string
}

// PolicyScript renders a bundle the caller already validated
// (portpolicy.ValidateBundle). Ids, CIDRs, ports and enums are all checked
// there, so only fixed template text and validated values reach nft.
func (c PolicyConfig) PolicyScript(b *dataplanev1.PolicyBundle, allow []netip.Prefix) string {
	if len(b.Policies) == 0 {
		return deleteTable("inet", PolicyTable)
	}
	rate := c.LogRate
	if rate == "" {
		rate = "30/minute"
	}
	a4, a6 := SplitFamilies(allow)
	var body strings.Builder
	body.WriteString(allowDecl("allow4", "ipv4_addr", a4))
	body.WriteString(allowDecl("allow6", "ipv6_addr", a6))
	has4, has6 := map[string]bool{}, map[string]bool{}
	for _, s := range b.Sets {
		var v4, v6 []string
		for _, cidr := range s.Cidrs {
			if netip.MustParsePrefix(cidr).Addr().Is4() {
				v4 = append(v4, cidr)
			} else {
				v6 = append(v6, cidr)
			}
		}
		if len(v4) > 0 {
			has4[s.Id] = true
			fmt.Fprintf(&body, "\tset s_%s_4 {\n\t\ttype ipv4_addr; flags interval; auto-merge;\n\t\telements = { %s }\n\t}\n", s.Id, strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			has6[s.Id] = true
			fmt.Fprintf(&body, "\tset s_%s_6 {\n\t\ttype ipv6_addr; flags interval; auto-merge;\n\t\telements = { %s }\n\t}\n", s.Id, strings.Join(v6, ", "))
		}
	}
	// Dispatch: new WAN connections only (policy changes never cut
	// established ones), allowlist first, then the first policy whose
	// protocol and public port match. Priority mangle: after conntrack and
	// the ban chains, before DNAT.
	fmt.Fprintf(&body, "\tchain dispatch {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"+
		"\t\t%saccept\n\t\tct state != new accept\n\t\tip saddr @allow4 accept\n\t\tip6 saddr @allow6 accept\n", notWAN("iifname", c.WAN.Get()))
	for _, p := range b.Policies {
		ports := make([]string, len(p.Ports))
		for i, r := range p.Ports {
			if r.From == r.To {
				ports[i] = fmt.Sprint(r.From)
			} else {
				ports[i] = fmt.Sprintf("%d-%d", r.From, r.To)
			}
		}
		fmt.Fprintf(&body, "\t\t%s dport { %s } jump p_%s\n", proto(p.Proto), strings.Join(ports, ", "), p.Id)
	}
	body.WriteString("\t}\n")
	for _, p := range b.Policies {
		fmt.Fprintf(&body, "\tchain p_%s {\n", p.Id)
		observe := p.Mode == dataplanev1.PolicyMode_POLICY_MODE_OBSERVE
		for i, r := range p.Rules {
			label := fmt.Sprintf("%s/r%d", p.Id, i)
			if has4[r.SetId] {
				body.WriteString(verdictRules(fmt.Sprintf("ip saddr @s_%s_4", r.SetId), label, r.Action, p, observe, rate))
			}
			if has6[r.SetId] {
				body.WriteString(verdictRules(fmt.Sprintf("ip6 saddr @s_%s_6", r.SetId), label, r.Action, p, observe, rate))
			}
		}
		body.WriteString(verdictRules("", p.Id+"/default", p.DefaultAction, p, observe, rate))
		body.WriteString("\t}\n")
	}
	return replaceTable("inet", PolicyTable, body.String())
}

func proto(p dataplanev1.L4Proto) string {
	if p == dataplanev1.L4Proto_L4_PROTO_UDP {
		return "udp"
	}
	return "tcp"
}

// verdictRules renders a match with its action. Drops are logged (rate
// limited) when the policy asks; observe mode logs what it would drop and
// accepts.
func verdictRules(match, label string, a dataplanev1.PolicyAction, p *dataplanev1.PortPolicy, observe bool, rate string) string {
	prefix := match
	if prefix != "" {
		prefix += " "
	}
	var b strings.Builder
	if a == dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT {
		fmt.Fprintf(&b, "\t\t%scounter accept comment %q\n", prefix, label)
		return b.String()
	}
	if p.LogDrops || observe {
		mode := ""
		if observe {
			mode = " observe"
		}
		fmt.Fprintf(&b, "\t\t%slimit rate %s log group 101 prefix \"POLICY-DROP: %s%s \" snaplen 128\n", prefix, rate, label, mode)
	}
	verdict := "drop"
	switch {
	case observe:
		verdict = "accept"
	case a == dataplanev1.PolicyAction_POLICY_ACTION_REJECT && p.Proto == dataplanev1.L4Proto_L4_PROTO_TCP:
		verdict = "reject with tcp reset"
	case a == dataplanev1.PolicyAction_POLICY_ACTION_REJECT:
		verdict = "reject"
	}
	fmt.Fprintf(&b, "\t\t%scounter %s comment %q\n", prefix, verdict, label)
	return b.String()
}

// PolicyCounters reads the packet counter of every labelled rule
// ("<policy>/r<n>", "<policy>/default").
func (h *Host) PolicyCounters(ctx context.Context) (map[string]uint64, error) {
	out, err := h.Output(ctx, "-j", "list", "table", "inet", PolicyTable)
	if err != nil {
		return nil, err
	}
	return ParseCounters(out)
}

// ParseCounters decodes rule counters from `nft -j list table` output.
func ParseCounters(out []byte) (map[string]uint64, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	res := map[string]uint64{}
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment == "" {
			continue
		}
		for _, e := range item.Rule.Expr {
			var c struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			}
			if json.Unmarshal(e, &c) == nil && c.Counter != nil {
				res[item.Rule.Comment] += c.Counter.Packets
			}
		}
	}
	return res, nil
}

// PolicyTablePresent reports whether the policy table exists.
func (h *Host) PolicyTablePresent(ctx context.Context) bool {
	_, err := h.Output(ctx, "list", "chain", "inet", PolicyTable, "dispatch")
	return err == nil
}
