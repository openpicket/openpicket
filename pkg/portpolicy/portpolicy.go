// Package portpolicy is the model of port policies — allow or block
// sources by country, AS, named list or CIDR on public (pre-DNAT) ports —
// its compilation into the data-only PolicyBundle sent to nodes, and the
// bundle validation every node applies before rendering nftables
// (docs/ARCHITECTURE.md §4.4).
package portpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/geoip"
)

// Actions and modes.
const (
	ActionAccept = "accept"
	ActionDrop   = "drop"
	ActionReject = "reject"

	ModeEnforce = "enforce"
	ModeObserve = "observe"
)

// Source selects addresses. A rule matches when the source address is in
// any of the listed countries, ASes, lists or CIDRs.
type Source struct {
	Countries []string `json:"countries,omitempty"`
	ASNs      []uint32 `json:"asns,omitempty"`
	Lists     []string `json:"lists,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`
}

// Rule is one source match and its action.
type Rule struct {
	Source Source `json:"source"`
	Action string `json:"action"`
}

// Scope selects the nodes a policy applies to.
type Scope struct {
	// All applies to every node (the default when nothing else is set).
	All bool `json:"all,omitempty"`
	// Nodes lists node ids.
	Nodes []string `json:"nodes,omitempty"`
	// Labels: every key must have one of the values.
	Labels map[string][]string `json:"labels,omitempty"`
}

// Matches reports whether a node is in scope.
func (s Scope) Matches(nodeID string, labels map[string]string) bool {
	if len(s.Nodes) == 0 && len(s.Labels) == 0 {
		return true
	}
	if slices.Contains(s.Nodes, nodeID) {
		return true
	}
	if len(s.Labels) == 0 {
		return false
	}
	for k, vals := range s.Labels {
		if !slices.Contains(vals, labels[k]) {
			return false
		}
	}
	return true
}

// PortRange is an inclusive range.
type PortRange struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}

// ParsePorts parses "443", "8000-8080, 25".
func ParsePorts(s string) ([]PortRange, error) {
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil || a == 0 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || b < a {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		out = append(out, PortRange{From: uint32(a), To: uint32(b)})
	}
	if len(out) == 0 {
		return nil, errors.New("no ports")
	}
	return out, nil
}

// Policy is a port policy.
type Policy struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Scope       Scope       `json:"scope"`
	Mode        string      `json:"mode"`
	Proto       string      `json:"proto"`
	Ports       []PortRange `json:"ports"`
	Rules       []Rule      `json:"rules"`
	Default     string      `json:"default"`
	LogDrops    bool        `json:"log_drops,omitempty"`
}

// List is a named address list (CIDRs and/or ASes).
type List struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs,omitempty"`
	ASNs  []uint32 `json:"asns,omitempty"`
}

var (
	idRe    = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	setIDRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// Validate checks a policy as edited (before saving).
func (p *Policy) Validate(lists map[string]bool) error {
	var errs []error
	if !idRe.MatchString(p.ID) {
		errs = append(errs, fmt.Errorf("id %q must match [a-z0-9_]{1,32}", p.ID))
	}
	if p.Mode != ModeEnforce && p.Mode != ModeObserve {
		errs = append(errs, fmt.Errorf("mode must be enforce or observe"))
	}
	if p.Proto != "tcp" && p.Proto != "udp" {
		errs = append(errs, fmt.Errorf("proto must be tcp or udp"))
	}
	if len(p.Ports) == 0 {
		errs = append(errs, errors.New("at least one port is required"))
	}
	for _, r := range p.Ports {
		if r.From < 1 || r.To > 65535 || r.From > r.To {
			errs = append(errs, fmt.Errorf("invalid port range %d-%d", r.From, r.To))
		}
	}
	if !validAction(p.Default) {
		errs = append(errs, fmt.Errorf("default must be accept, drop or reject"))
	}
	if len(p.Rules) > MaxRules {
		errs = append(errs, fmt.Errorf("at most %d rules", MaxRules))
	}
	for i, r := range p.Rules {
		if !validAction(r.Action) {
			errs = append(errs, fmt.Errorf("rule %d: action must be accept, drop or reject", i+1))
		}
		s := r.Source
		if len(s.Countries)+len(s.ASNs)+len(s.Lists)+len(s.CIDRs) == 0 {
			errs = append(errs, fmt.Errorf("rule %d: no source", i+1))
		}
		for _, c := range s.Countries {
			if len(c) != 2 {
				errs = append(errs, fmt.Errorf("rule %d: invalid country code %q", i+1, c))
			}
		}
		for _, l := range s.Lists {
			if !lists[l] {
				errs = append(errs, fmt.Errorf("rule %d: unknown list %q", i+1, l))
			}
		}
		for _, c := range s.CIDRs {
			if _, err := parseNet(c); err != nil {
				errs = append(errs, fmt.Errorf("rule %d: %v", i+1, err))
			}
		}
	}
	return errors.Join(errs...)
}

func validAction(a string) bool { return a == ActionAccept || a == ActionDrop || a == ActionReject }

func parseNet(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid network %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// UsesGeo reports whether a policy needs the country or ASN database.
func (p *Policy) UsesGeo(lists map[string]List) (country, asn bool) {
	for _, r := range p.Rules {
		country = country || len(r.Source.Countries) > 0
		asn = asn || len(r.Source.ASNs) > 0
		for _, l := range r.Source.Lists {
			asn = asn || len(lists[l].ASNs) > 0
		}
	}
	return country, asn
}

// Limits of a bundle (also enforced by nodes).
const (
	MaxPolicies = 256
	MaxRules    = 64
)

var actions = map[string]dataplanev1.PolicyAction{
	ActionAccept: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT,
	ActionDrop:   dataplanev1.PolicyAction_POLICY_ACTION_DROP,
	ActionReject: dataplanev1.PolicyAction_POLICY_ACTION_REJECT,
}

// Skipped is a policy that could not be compiled for a bundle.
type Skipped struct {
	ID     string
	Reason string
	// Stale: the last version that compiled is deployed instead; otherwise
	// the policy is left out (it never compiled).
	Stale bool `json:",omitempty"`
}

// Compiled is one policy ready for nodes: the policy and its sets. It does
// not depend on the node.
type Compiled struct {
	Policy *dataplanev1.PortPolicy
	Sets   []*dataplanev1.NamedSet
}

// Result is the outcome of compiling a policy for the cluster. When Err is
// set, Compiled is the last version that compiled (or nil if none did):
// a missing GeoIP database must not remove a protection already deployed.
type Result struct {
	Compiled *Compiled
	Err      string
}

// CompilePolicy resolves the sources of a policy to CIDRs. It fails when a
// source cannot be resolved (no GeoIP database, unknown list), so a
// missing upload never deploys a half policy.
func CompilePolicy(p Policy, lists map[string]List, geo *geoip.DB) (*Compiled, error) {
	pp := &dataplanev1.PortPolicy{Id: p.ID, Mode: dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, LogDrops: p.LogDrops,
		DefaultAction: actions[p.Default], Proto: dataplanev1.L4Proto_L4_PROTO_TCP}
	if p.Mode == ModeObserve {
		pp.Mode = dataplanev1.PolicyMode_POLICY_MODE_OBSERVE
	}
	if p.Proto == "udp" {
		pp.Proto = dataplanev1.L4Proto_L4_PROTO_UDP
	}
	for _, r := range p.Ports {
		pp.Ports = append(pp.Ports, &dataplanev1.PortRange{From: r.From, To: r.To})
	}
	c := &Compiled{Policy: pp}
	for i, r := range p.Rules {
		cidrs, err := resolve(r.Source, lists, geo)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		id := fmt.Sprintf("%s_r%d", p.ID, i)
		c.Sets = append(c.Sets, &dataplanev1.NamedSet{Id: id, Cidrs: cidrs})
		pp.Rules = append(pp.Rules, &dataplanev1.PolicyRule{SetId: id, Action: actions[r.Action]})
	}
	return c, nil
}

// Assemble builds the bundle of one node from compiled policies: the
// enabled policies in scope, in order. Policies that failed to compile are
// reported; their last good version is used when there is one.
func Assemble(version uint64, policies []Policy, results map[string]Result, nodeID string, labels map[string]string) (*dataplanev1.PolicyBundle, []Skipped) {
	b := &dataplanev1.PolicyBundle{Version: version}
	var skipped []Skipped
	for _, p := range policies {
		if !p.Enabled || !p.Scope.Matches(nodeID, labels) {
			continue
		}
		r := results[p.ID]
		if r.Err != "" {
			skipped = append(skipped, Skipped{ID: p.ID, Reason: r.Err, Stale: r.Compiled != nil})
		}
		if r.Compiled == nil {
			continue
		}
		b.Policies = append(b.Policies, r.Compiled.Policy)
		b.Sets = append(b.Sets, r.Compiled.Sets...)
	}
	return b, skipped
}

// Compile compiles the policies and assembles the bundle of one node,
// without last good versions.
func Compile(version uint64, policies []Policy, lists map[string]List, geo *geoip.DB, nodeID string, labels map[string]string) (*dataplanev1.PolicyBundle, []Skipped) {
	results := map[string]Result{}
	for _, p := range policies {
		c, err := CompilePolicy(p, lists, geo)
		if err != nil {
			results[p.ID] = Result{Err: err.Error()}
			continue
		}
		results[p.ID] = Result{Compiled: c}
	}
	return Assemble(version, policies, results, nodeID, labels)
}

func resolve(s Source, lists map[string]List, geo *geoip.DB) ([]string, error) {
	var ps []netip.Prefix
	for _, c := range s.Countries {
		got, err := geo.Country(c)
		if err != nil {
			return nil, fmt.Errorf("country %s: %w", c, err)
		}
		ps = append(ps, got...)
	}
	asns := slices.Clone(s.ASNs)
	cidrs := slices.Clone(s.CIDRs)
	for _, name := range s.Lists {
		l, ok := lists[name]
		if !ok {
			return nil, fmt.Errorf("unknown list %q", name)
		}
		asns, cidrs = append(asns, l.ASNs...), append(cidrs, l.CIDRs...)
	}
	for _, a := range asns {
		got, err := geo.ASN(a)
		if err != nil {
			return nil, fmt.Errorf("AS%d: %w", a, err)
		}
		ps = append(ps, got...)
	}
	for _, c := range cidrs {
		p, err := parseNet(c)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	ps = geoip.Aggregate(ps)
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out, nil
}

// Limits a node applies to bundles.
type Limits struct {
	MaxElements int
}

// ValidateBundle is the node-side contract: a bundle that fails it is
// refused as a whole and the previous one stays (§4.4). It returns the
// total number of set elements.
func ValidateBundle(b *dataplanev1.PolicyBundle, lim Limits) (int, error) {
	if len(b.Policies) > MaxPolicies {
		return 0, fmt.Errorf("too many policies (%d > %d)", len(b.Policies), MaxPolicies)
	}
	sets := map[string]bool{}
	total := 0
	for _, s := range b.Sets {
		if !setIDRe.MatchString(s.Id) {
			return 0, fmt.Errorf("invalid set id %q", s.Id)
		}
		if sets[s.Id] {
			return 0, fmt.Errorf("duplicate set id %q", s.Id)
		}
		sets[s.Id] = true
		for _, c := range s.Cidrs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return 0, fmt.Errorf("set %s: invalid CIDR %q", s.Id, c)
			}
		}
		total += len(s.Cidrs)
	}
	if lim.MaxElements > 0 && total > lim.MaxElements {
		return 0, fmt.Errorf("too many set elements (%d > %d)", total, lim.MaxElements)
	}
	ids := map[string]bool{}
	for _, p := range b.Policies {
		if !idRe.MatchString(p.Id) {
			return 0, fmt.Errorf("invalid policy id %q", p.Id)
		}
		if ids[p.Id] {
			return 0, fmt.Errorf("duplicate policy id %q", p.Id)
		}
		ids[p.Id] = true
		switch p.Mode {
		case dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, dataplanev1.PolicyMode_POLICY_MODE_OBSERVE:
		default:
			return 0, fmt.Errorf("policy %s: unknown mode", p.Id)
		}
		switch p.Proto {
		case dataplanev1.L4Proto_L4_PROTO_TCP, dataplanev1.L4Proto_L4_PROTO_UDP:
		default:
			return 0, fmt.Errorf("policy %s: unknown protocol", p.Id)
		}
		if len(p.Ports) == 0 || len(p.Ports) > 64 {
			return 0, fmt.Errorf("policy %s: 1 to 64 port ranges", p.Id)
		}
		for _, r := range p.Ports {
			if r.From < 1 || r.To > 65535 || r.From > r.To {
				return 0, fmt.Errorf("policy %s: invalid port range %d-%d", p.Id, r.From, r.To)
			}
		}
		if len(p.Rules) > MaxRules {
			return 0, fmt.Errorf("policy %s: too many rules", p.Id)
		}
		if !knownAction(p.DefaultAction) {
			return 0, fmt.Errorf("policy %s: unknown default action", p.Id)
		}
		for _, r := range p.Rules {
			if !sets[r.SetId] {
				return 0, fmt.Errorf("policy %s: undefined set %q", p.Id, r.SetId)
			}
			if !knownAction(r.Action) {
				return 0, fmt.Errorf("policy %s: unknown action", p.Id)
			}
		}
	}
	return total, nil
}

func knownAction(a dataplanev1.PolicyAction) bool {
	switch a {
	case dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT, dataplanev1.PolicyAction_POLICY_ACTION_DROP, dataplanev1.PolicyAction_POLICY_ACTION_REJECT:
		return true
	}
	return false
}
