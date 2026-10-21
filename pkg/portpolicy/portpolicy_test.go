package portpolicy

import (
	"strings"
	"testing"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/geoip"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
)

func testGeo(t *testing.T) *geoip.DB {
	db, err := geoip.Open(
		geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN", "1.0.1.0/24": "CN", "2.0.0.0/16": "KR"}),
		geoiptest.ASN(t, map[string]uint32{"8.8.8.0/24": 15169, "8.8.4.0/24": 15169}))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// The two examples of the requirements: "443/tcp: block CN" and
// "587/tcp: allow KR and Google".
func examples() ([]Policy, map[string]List) {
	lists := map[string]List{"google": {Name: "google", ASNs: []uint32{15169}, CIDRs: []string{"142.250.0.0/15"}}}
	return []Policy{
		{ID: "https_block_cn", Enabled: true, Mode: ModeEnforce, Proto: "tcp", Ports: []PortRange{{443, 443}},
			Rules: []Rule{{Source: Source{Countries: []string{"CN"}}, Action: ActionDrop}}, Default: ActionAccept},
		{ID: "smtp_submission", Enabled: true, Mode: ModeEnforce, Proto: "tcp", Ports: []PortRange{{587, 587}}, LogDrops: true,
			Scope:   Scope{Labels: map[string][]string{"site": {"seoul"}}},
			Rules:   []Rule{{Source: Source{Countries: []string{"KR"}}, Action: ActionAccept}, {Source: Source{Lists: []string{"google"}}, Action: ActionAccept}},
			Default: ActionDrop},
		{ID: "disabled", Enabled: false, Mode: ModeEnforce, Proto: "tcp", Ports: []PortRange{{22, 22}}, Default: ActionDrop},
	}, lists
}

func TestCompile(t *testing.T) {
	ps, lists := examples()
	geo := testGeo(t)
	b, skipped := Compile(7, ps, lists, geo, "router-01", map[string]string{"site": "seoul"})
	if len(skipped) != 0 || b.Version != 7 || len(b.Policies) != 2 || len(b.Sets) != 3 {
		t.Fatalf("bundle = %v skipped = %v", b, skipped)
	}
	if got := strings.Join(b.Sets[0].Cidrs, ","); got != "1.0.0.0/23" {
		t.Fatalf("CN set = %s", got)
	}
	if got := strings.Join(b.Sets[2].Cidrs, ","); got != "8.8.4.0/24,8.8.8.0/24,142.250.0.0/15" {
		t.Fatalf("google set = %s", got)
	}
	if p := b.Policies[1]; p.DefaultAction != dataplanev1.PolicyAction_POLICY_ACTION_DROP || !p.LogDrops || len(p.Rules) != 2 {
		t.Fatalf("smtp = %v", p)
	}
	if n, err := ValidateBundle(b, Limits{MaxElements: 100}); err != nil || n != 5 {
		t.Fatalf("validate: %d %v", n, err)
	}
	// Out of scope: busan gets only the global policy.
	if b2, _ := Compile(7, ps, lists, geo, "router-02", map[string]string{"site": "busan"}); len(b2.Policies) != 1 {
		t.Fatalf("busan = %v", b2.Policies)
	}
	// Without GeoIP databases the geo policies are left out, not half
	// deployed.
	noGeo, _ := geoip.Open(nil, nil)
	b3, skipped := Compile(7, ps, lists, noGeo, "router-01", map[string]string{"site": "seoul"})
	if len(b3.Policies) != 0 || len(skipped) != 2 {
		t.Fatalf("no geo: %v %v", b3.Policies, skipped)
	}
}

func TestValidate(t *testing.T) {
	ps, lists := examples()
	known := map[string]bool{}
	for n := range lists {
		known[n] = true
	}
	for _, p := range ps {
		if err := p.Validate(known); err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
	}
	bad := Policy{ID: "Bad Id", Mode: "maybe", Proto: "icmp", Default: "allow", Rules: []Rule{{Action: ActionDrop}, {Source: Source{Lists: []string{"nope"}, CIDRs: []string{"x"}}, Action: ActionDrop}}}
	err := bad.Validate(known)
	for _, want := range []string{"id", "mode", "proto", "port", "default", "no source", "unknown list", "invalid network"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if r, err := ParsePorts("25, 8000-8080"); err != nil || len(r) != 2 || r[1].To != 8080 {
		t.Fatalf("ports = %v %v", r, err)
	}
	for _, s := range []string{"", "0", "70000", "90-80", "a"} {
		if _, err := ParsePorts(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestValidateBundleRefuses(t *testing.T) {
	ok := func() *dataplanev1.PolicyBundle {
		return &dataplanev1.PolicyBundle{Version: 1,
			Sets: []*dataplanev1.NamedSet{{Id: "p_r0", Cidrs: []string{"1.0.0.0/24"}}},
			Policies: []*dataplanev1.PortPolicy{{Id: "p", Mode: dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, Proto: dataplanev1.L4Proto_L4_PROTO_TCP,
				Ports: []*dataplanev1.PortRange{{From: 443, To: 443}}, DefaultAction: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT,
				Rules: []*dataplanev1.PolicyRule{{SetId: "p_r0", Action: dataplanev1.PolicyAction_POLICY_ACTION_DROP}}}}}
	}
	cases := map[string]func(b *dataplanev1.PolicyBundle){
		"injected id":    func(b *dataplanev1.PolicyBundle) { b.Policies[0].Id = `p; flush ruleset` },
		"injected set":   func(b *dataplanev1.PolicyBundle) { b.Sets[0].Id = `x } ; flush ruleset ; set y {` },
		"bad cidr":       func(b *dataplanev1.PolicyBundle) { b.Sets[0].Cidrs = []string{"1.0.0.0/24 } flush ruleset"} },
		"undefined set":  func(b *dataplanev1.PolicyBundle) { b.Policies[0].Rules[0].SetId = "other" },
		"bad port":       func(b *dataplanev1.PolicyBundle) { b.Policies[0].Ports[0].To = 70000 },
		"unknown action": func(b *dataplanev1.PolicyBundle) { b.Policies[0].DefaultAction = 9 },
		"unknown mode":   func(b *dataplanev1.PolicyBundle) { b.Policies[0].Mode = 0 },
		"too many":       func(b *dataplanev1.PolicyBundle) { b.Sets[0].Cidrs = append(b.Sets[0].Cidrs, "2.0.0.0/8", "3.0.0.0/8") },
	}
	for name, mutate := range cases {
		b := ok()
		mutate(b)
		if _, err := ValidateBundle(b, Limits{MaxElements: 2}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ValidateBundle(ok(), Limits{MaxElements: 2}); err != nil {
		t.Fatal(err)
	}
}
