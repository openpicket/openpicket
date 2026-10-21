package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// BanTable is the table enforcing decisions (docs/ARCHITECTURE.md §4.4).
// It is created once and then only its set elements change, so the
// timeouts of existing elements are never touched by unrelated changes
// (port policies live in their own table).
const BanTable = "openpicket_ban"

// Ban set names: direction x family x (address | range). Addresses and
// ranges use separate sets so that an address inside a blocked range never
// conflicts with it.
var banSets = []string{"in4", "in4r", "in6", "in6r", "both4", "both4r", "both6", "both6r"}

// SetName returns the set holding a value.
func SetName(both, v6, isRange bool) string {
	s := "in"
	if both {
		s = "both"
	}
	if v6 {
		s += "6"
	} else {
		s += "4"
	}
	if isRange {
		s += "r"
	}
	return s
}

// BanSets returns every ban set name.
func BanSets() []string { return append([]string(nil), banSets...) }

// BanConfig is the agent-owned part of the ban table.
type BanConfig struct {
	// WAN is held in the table's wan set, replaced when it changes
	// (WANScript).
	WAN *WAN
	// Egress also blocks traffic to BOTH decisions leaving through the WAN
	// (and logs it to NFLOG group 102).
	Egress bool
	// EgressLogRate limits the BAN-EGRESS log ("10/second").
	EgressLogRate string
}

func setDecl(name string) string {
	typ := "ipv4_addr"
	if strings.Contains(name, "6") {
		typ = "ipv6_addr"
	}
	flags := "timeout"
	if strings.HasSuffix(name, "r") {
		flags = "interval, timeout"
	}
	return fmt.Sprintf("\tset %s {\n\t\ttype %s; flags %s;\n\t}\n", name, typ, flags)
}

func allowDecl(name, typ string, elems []netip.Prefix) string {
	s := fmt.Sprintf("\tset %s {\n\t\ttype %s; flags interval; auto-merge;\n", name, typ)
	if len(elems) > 0 {
		s += "\t\telements = { " + joinPrefixes(elems) + " }\n"
	}
	return s + "\t}\n"
}

func joinPrefixes(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ", ")
}

// SplitFamilies separates IPv4 and IPv6 prefixes.
func SplitFamilies(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// Script creates the ban table with empty ban sets.
func (c BanConfig) Script(allow []netip.Prefix) string {
	a4, a6 := SplitFamilies(allow)
	var b strings.Builder
	b.WriteString(wanDecl(c.WAN.Get()))
	b.WriteString(allowDecl("allow4", "ipv4_addr", a4))
	b.WriteString(allowDecl("allow6", "ipv6_addr", a6))
	for _, s := range banSets {
		b.WriteString(setDecl(s))
	}
	// Conntrack does not exist yet at raw priority, so drop only packets
	// that cannot be replies: TCP SYN without ACK and ICMP echo requests.
	// BOTH drops everything from the address.
	b.WriteString(`	chain guard {
		type filter hook prerouting priority raw - 10; policy accept;
		iifname != @wan accept
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		ip saddr @both4 counter drop
		ip saddr @both4r counter drop
		ip6 saddr @both6 counter drop
		ip6 saddr @both6r counter drop
		ip saddr @in4 tcp flags & (syn | ack) == syn counter drop
		ip saddr @in4r tcp flags & (syn | ack) == syn counter drop
		ip6 saddr @in6 tcp flags & (syn | ack) == syn counter drop
		ip6 saddr @in6r tcp flags & (syn | ack) == syn counter drop
		ip saddr @in4 icmp type echo-request counter drop
		ip saddr @in4r icmp type echo-request counter drop
		ip6 saddr @in6 icmpv6 type echo-request counter drop
		ip6 saddr @in6r icmpv6 type echo-request counter drop
	}
`)
	// After conntrack: the remaining new connections of INBOUND addresses
	// (UDP and others); replies to connections opened from inside pass.
	b.WriteString(`	chain guard_ct {
		type filter hook prerouting priority mangle - 10; policy accept;
		iifname != @wan accept
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		ip saddr @in4 ct state new counter drop
		ip saddr @in4r ct state new counter drop
		ip6 saddr @in6 ct state new counter drop
		ip6 saddr @in6r ct state new counter drop
	}
`)
	if c.Egress {
		rate := c.EgressLogRate
		if rate == "" {
			rate = "10/second"
		}
		fmt.Fprintf(&b, `	chain egress {
		type filter hook forward priority filter - 10; policy accept;
		oifname != @wan accept
		ip daddr @allow4 accept
		ip6 daddr @allow6 accept
		ip daddr @both4 limit rate %[1]s log group 102 prefix "BAN-EGRESS: " snaplen 128
		ip daddr @both4r limit rate %[1]s log group 102 prefix "BAN-EGRESS: " snaplen 128
		ip6 daddr @both6 limit rate %[1]s log group 102 prefix "BAN-EGRESS: " snaplen 128
		ip6 daddr @both6r limit rate %[1]s log group 102 prefix "BAN-EGRESS: " snaplen 128
		ip daddr @both4 counter drop
		ip daddr @both4r counter drop
		ip6 daddr @both6 counter drop
		ip6 daddr @both6r counter drop
	}
	chain egress_local {
		type filter hook output priority filter - 10; policy accept;
		oifname != @wan accept
		ip daddr @both4 counter drop
		ip daddr @both4r counter drop
		ip6 daddr @both6 counter drop
		ip6 daddr @both6r counter drop
	}
`, rate)
	}
	return replaceTable("inet", BanTable, b.String())
}

// AllowScript replaces the allowlist sets.
func AllowScript(allow []netip.Prefix) string {
	a4, a6 := SplitFamilies(allow)
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s allow4\nflush set inet %s allow6\n", BanTable, BanTable)
	if len(a4) > 0 {
		fmt.Fprintf(&b, "add element inet %s allow4 { %s }\n", BanTable, joinPrefixes(a4))
	}
	if len(a6) > 0 {
		fmt.Fprintf(&b, "add element inet %s allow6 { %s }\n", BanTable, joinPrefixes(a6))
	}
	return b.String()
}

// Element is a set element with its timeout.
type Element struct {
	Set     string
	Value   string
	Timeout time.Duration
}

const opChunk = 2000

// ElementsScript renders deletions then additions, in chunks.
func ElementsScript(dels, adds []Element) string {
	var b strings.Builder
	group := func(els []Element, verb string, withTimeout bool) {
		bySet := map[string][]Element{}
		var order []string
		for _, e := range els {
			if _, ok := bySet[e.Set]; !ok {
				order = append(order, e.Set)
			}
			bySet[e.Set] = append(bySet[e.Set], e)
		}
		for _, set := range order {
			list := bySet[set]
			for i := 0; i < len(list); i += opChunk {
				end := min(i+opChunk, len(list))
				parts := make([]string, 0, end-i)
				for _, e := range list[i:end] {
					if withTimeout {
						parts = append(parts, fmt.Sprintf("%s timeout %ds", e.Value, max(int64(e.Timeout/time.Second), 1)))
					} else {
						parts = append(parts, e.Value)
					}
				}
				fmt.Fprintf(&b, "%s element inet %s %s { %s }\n", verb, BanTable, set, strings.Join(parts, ", "))
			}
		}
	}
	group(dels, "delete", false)
	group(adds, "add", true)
	return b.String()
}

// listedSet is the JSON form of `nft -j list set`.
type listedSet struct {
	Nftables []struct {
		Set *struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// ListElements returns the elements of a ban set with their remaining
// time (expires).
func (h *Host) ListElements(ctx context.Context, set string) (map[string]time.Duration, error) {
	out, err := h.Output(ctx, "-j", "list", "set", "inet", BanTable, set)
	if err != nil {
		return nil, err
	}
	return ParseElements(out)
}

// ParseElements decodes `nft -j list set` output.
func ParseElements(out []byte) (map[string]time.Duration, error) {
	var ls listedSet
	if err := json.Unmarshal(out, &ls); err != nil {
		return nil, err
	}
	res := map[string]time.Duration{}
	for _, item := range ls.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			v, exp, ok := parseElem(raw)
			if ok {
				res[v] = exp
			}
		}
	}
	return res, nil
}

type prefixJSON struct {
	Prefix *struct {
		Addr string `json:"addr"`
		Len  int    `json:"len"`
	} `json:"prefix"`
}

func parseVal(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	var p prefixJSON
	if json.Unmarshal(raw, &p) == nil && p.Prefix != nil {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len), true
	}
	return "", false
}

func parseElem(raw json.RawMessage) (string, time.Duration, bool) {
	var wrapped struct {
		Elem *struct {
			Val     json.RawMessage `json:"val"`
			Expires float64         `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && wrapped.Elem != nil {
		v, ok := parseVal(wrapped.Elem.Val)
		return v, time.Duration(wrapped.Elem.Expires * float64(time.Second)), ok
	}
	v, ok := parseVal(raw)
	return v, 0, ok
}

// BanTablePresent reports whether the ban table and its guard chain exist
// (in their current form: a table of earlier versions is recreated).
func (h *Host) BanTablePresent(ctx context.Context) bool {
	out, err := h.Output(ctx, "list", "chain", "inet", BanTable, "guard")
	return err == nil && strings.Contains(string(out), "@both4") && strings.Contains(string(out), "@wan")
}
