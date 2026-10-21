package nft

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

// WAN is the list of interfaces facing the internet. On OpenWrt it follows
// the devices of the fw4 WAN zones, so it changes at runtime; the tables
// read it whenever they are rendered.
type WAN struct{ p atomic.Pointer[[]string] }

// NewWAN returns a WAN list holding names.
func NewWAN(names ...string) *WAN {
	w := &WAN{}
	w.Set(names)
	return w
}

// Get returns the names, sorted.
func (w *WAN) Get() []string {
	if w == nil {
		return nil
	}
	if p := w.p.Load(); p != nil {
		return *p
	}
	return nil
}

// Set replaces the names and reports a change.
func (w *WAN) Set(names []string) bool {
	n := slices.Clone(names)
	slices.Sort(n)
	n = slices.Compact(n)
	if old := w.p.Load(); old != nil && slices.Equal(*old, n) {
		return false
	}
	w.p.Store(&n)
	return true
}

// ifnameRe matches interface names (IFNAMSIZ), with an optional trailing
// wildcard as fw4 renders "tun+" devices.
var ifnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9_.@-]{1,15}|[A-Za-z0-9_.@-]{1,14}\*)$`)

// ValidIfname reports whether s can be used as an interface name in rules.
func ValidIfname(s string) bool { return ifnameRe.MatchString(s) }

// notWAN is the start of a rule matching packets that did not come in
// through the WAN ("iifname != { ... } "), or "" when there is no WAN: the
// rule then matches everything, so the chain does nothing.
func notWAN(dir string, names []string) string {
	if len(names) == 0 {
		return ""
	}
	return dir + " != " + quoteSet(names) + " "
}

// wanDecl declares the ban table's WAN set; its elements are replaced
// without touching the ban sets (WANScript).
func wanDecl(names []string) string {
	s := "\tset wan {\n\t\ttype ifname; flags interval;\n"
	if len(names) > 0 {
		s += "\t\telements = " + quoteSet(names) + "\n"
	}
	return s + "\t}\n"
}

// WANScript replaces the elements of the ban table's WAN set.
func WANScript(names []string) string {
	s := fmt.Sprintf("flush set inet %s wan\n", BanTable)
	if len(names) > 0 {
		s += fmt.Sprintf("add element inet %s wan %s\n", BanTable, quoteSet(names))
	}
	return s
}

// fw4ZoneRule matches the rules of fw4's input chain sending a zone's
// devices to its chain: `iifname "pppoe-wan" jump input_wan` or
// `iifname { "eth1", "wwan0" } jump input_wan`.
var (
	fw4ZoneRule = regexp.MustCompile(`iifname (\{[^}]*\}|"[^"]*") .*jump input_([A-Za-z0-9_]+)`)
	quoted      = regexp.MustCompile(`"([^"]*)"`)
)

// Fw4ZoneDevices returns the devices of each zone, read from fw4's rules
// (fw4 resolves the zone's networks to their current devices). A zone
// defined by subnets only, or whose networks are all down, has none.
func (h *Host) Fw4ZoneDevices(ctx context.Context) (map[string][]string, error) {
	out, err := h.Output(ctx, "list", "chain", "inet", "fw4", "input")
	if err != nil {
		return nil, fmt.Errorf("read fw4 zones: %w", err)
	}
	return ParseFw4Zones(string(out)), nil
}

// ParseFw4Zones parses `nft list chain inet fw4 input`. Names that are not
// valid interface names are left out.
func ParseFw4Zones(out string) map[string][]string {
	zones := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		m := fw4ZoneRule.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			if ValidIfname(q[1]) && !slices.Contains(zones[m[2]], q[1]) {
				zones[m[2]] = append(zones[m[2]], q[1])
			}
		}
	}
	return zones
}
