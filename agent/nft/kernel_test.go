package nft

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/platform"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// nftCheck validates a script with `nft -c` on a real kernel
// (scripts/nft-check.sh, docker). Enabled by OPENPICKET_TEST_NFT=1.
func nftCheck(t *testing.T, script string) {
	t.Helper()
	if os.Getenv("OPENPICKET_TEST_NFT") != "1" {
		t.Skip("OPENPICKET_TEST_NFT not set")
	}
	var cmd *exec.Cmd
	if os.Getenv("OPENPICKET_TEST_NETNS") == "1" {
		// Already inside the test container (scripts/netns-test.sh).
		cmd = exec.Command("nft", "-c", "-f", "-")
	} else {
		_, file, _, _ := runtime.Caller(0)
		cmd = exec.Command(filepath.Join(filepath.Dir(file), "..", "..", "scripts", "nft-check.sh"))
	}
	cmd.Stdin = bytes.NewBufferString(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the script: %v\n%s\n--- script ---\n%s", err, out, script)
	}
}

func TestKernelAcceptsWANReject(t *testing.T) {
	w := &WANReject{WAN: []string{"eth0", "pppoe-wan"}, Rate: "30/minute", Burst: 10, Group: 100, IgnorePorts: []uint16{22, 51820}}
	nftCheck(t, w.Table())
	w.noSocket = true
	nftCheck(t, w.Table())
	// The fw4 snippet goes into the zone's input chain (a regular chain
	// jumped to from the input hook).
	nftCheck(t, "table inet fw4 {\n\tchain input_wan {\n\t\t"+w.Fw4Snippet()+"\t}\n"+
		"\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tjump input_wan\n\t}\n}\n")
}

func TestKernelAcceptsBanTable(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("198.51.100.1/32")}
	nftCheck(t, BanConfig{WAN: []string{"wan"}, Egress: true}.Script(allow))
	nftCheck(t, BanConfig{WAN: []string{"eth0", "ppp0"}}.Script(nil))
}

// TestNetnsBanElements applies the table on a real kernel and exercises the
// element operations the enforcer uses (scripts/netns-test.sh).
func TestNetnsBanElements(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	h := &Host{Exec: platform.LocalExec{}}
	ctx := context.Background()
	allow := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	if err := h.Apply(ctx, BanConfig{WAN: []string{"wan"}, Egress: true}.Script(allow)); err != nil {
		t.Fatal(err)
	}
	if !h.BanTablePresent(ctx) {
		t.Fatal("table not present")
	}
	adds := []Element{
		{Set: "in4", Value: "198.51.100.4", Timeout: time.Hour},
		{Set: "in4r", Value: "203.0.113.0/24", Timeout: 2 * time.Hour},
		{Set: "both6", Value: "2001:db8:99::1", Timeout: 30 * time.Minute},
		{Set: "in4r", Value: "203.0.114.0/24", Timeout: time.Hour},
	}
	if err := h.Apply(ctx, ElementsScript(nil, adds)); err != nil {
		t.Fatal(err)
	}
	in4, err := h.ListElements(ctx, "in4")
	if err != nil {
		t.Fatal(err)
	}
	if exp, ok := in4["198.51.100.4"]; !ok || exp < 59*time.Minute || exp > time.Hour {
		t.Fatalf("in4 = %v", in4)
	}
	in4r, _ := h.ListElements(ctx, "in4r")
	if _, ok := in4r["203.0.113.0/24"]; !ok || len(in4r) != 2 {
		t.Fatalf("in4r = %v", in4r)
	}
	both6, _ := h.ListElements(ctx, "both6")
	if _, ok := both6["2001:db8:99::1"]; !ok {
		t.Fatalf("both6 = %v", both6)
	}
	// Changing an element's timeout: delete and add in one transaction.
	if err := h.Apply(ctx, ElementsScript([]Element{{Set: "in4", Value: "198.51.100.4"}}, []Element{{Set: "in4", Value: "198.51.100.4", Timeout: 10 * time.Minute}})); err != nil {
		t.Fatal(err)
	}
	in4, _ = h.ListElements(ctx, "in4")
	if exp := in4["198.51.100.4"]; exp > 10*time.Minute || exp < 9*time.Minute {
		t.Fatalf("updated timeout = %v", exp)
	}
	// Deleting an element that is gone fails the whole transaction (the
	// enforcer then resyncs from the listing).
	if err := h.Apply(ctx, ElementsScript([]Element{{Set: "in4", Value: "198.51.100.200"}}, nil)); err == nil {
		t.Fatal("deleting a missing element should fail")
	}
	if err := h.Apply(ctx, AllowScript([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:1::/48")})); err != nil {
		t.Fatal(err)
	}
}

func examplePolicyBundle() *dataplanev1.PolicyBundle {
	return &dataplanev1.PolicyBundle{Version: 3,
		Sets: []*dataplanev1.NamedSet{
			{Id: "https_block_cn_r0", Cidrs: []string{"1.0.0.0/23", "2001:db8:cc::/48"}},
			{Id: "smtp_submission_r0", Cidrs: []string{"2.0.0.0/16"}},
			{Id: "smtp_submission_r1", Cidrs: []string{"8.8.4.0/24", "8.8.8.0/24", "142.250.0.0/15"}},
		},
		Policies: []*dataplanev1.PortPolicy{
			{Id: "https_block_cn", Mode: dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, Proto: dataplanev1.L4Proto_L4_PROTO_TCP,
				Ports: []*dataplanev1.PortRange{{From: 443, To: 443}}, DefaultAction: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT,
				Rules: []*dataplanev1.PolicyRule{{SetId: "https_block_cn_r0", Action: dataplanev1.PolicyAction_POLICY_ACTION_DROP}}},
			{Id: "smtp_submission", Mode: dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, Proto: dataplanev1.L4Proto_L4_PROTO_TCP, LogDrops: true,
				Ports: []*dataplanev1.PortRange{{From: 587, To: 587}, {From: 465, To: 465}}, DefaultAction: dataplanev1.PolicyAction_POLICY_ACTION_REJECT,
				Rules: []*dataplanev1.PolicyRule{{SetId: "smtp_submission_r0", Action: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT},
					{SetId: "smtp_submission_r1", Action: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT}}},
			{Id: "dns_observe", Mode: dataplanev1.PolicyMode_POLICY_MODE_OBSERVE, Proto: dataplanev1.L4Proto_L4_PROTO_UDP,
				Ports: []*dataplanev1.PortRange{{From: 5300, To: 5399}}, DefaultAction: dataplanev1.PolicyAction_POLICY_ACTION_DROP},
		}}
}

func TestKernelAcceptsPolicyTable(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	s := PolicyConfig{WAN: []string{"wan"}}.PolicyScript(examplePolicyBundle(), allow)
	for _, want := range []string{
		"tcp dport { 443 } jump p_https_cn_block",
		"tcp dport { 587, 465 } jump p_smtp_submission",
		"udp dport { 5300-5399 } jump p_dns_observe",
		`ip saddr @s_https_block_cn_r0_4 counter drop comment "https_block_cn/r0"`,
		`ip6 saddr @s_https_block_cn_r0_6 counter drop`,
		`counter reject with tcp reset comment "smtp_submission/default"`,
		`log group 101 prefix "POLICY-DROP: smtp_submission/default "`,
		`log group 101 prefix "POLICY-DROP: dns_observe/default observe "`,
		`counter accept comment "dns_observe/default"`,
	} {
		if want == "tcp dport { 443 } jump p_https_cn_block" {
			want = "tcp dport { 443 } jump p_https_block_cn"
		}
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	nftCheck(t, s)
	if got := (PolicyConfig{WAN: []string{"wan"}}).PolicyScript(&dataplanev1.PolicyBundle{}, nil); !strings.Contains(got, "delete table inet openpicket_policy") {
		t.Fatalf("empty bundle: %q", got)
	}
}

func TestNetnsPolicyCounters(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	h := &Host{Exec: platform.LocalExec{}}
	ctx := context.Background()
	if err := h.Apply(ctx, PolicyConfig{WAN: []string{"wan"}}.PolicyScript(examplePolicyBundle(), nil)); err != nil {
		t.Fatal(err)
	}
	if !h.PolicyTablePresent(ctx) {
		t.Fatal("policy table missing")
	}
	c, err := h.PolicyCounters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"https_block_cn/r0", "https_block_cn/default", "smtp_submission/r1", "dns_observe/default"} {
		if _, ok := c[k]; !ok {
			t.Fatalf("counter %s missing in %v", k, c)
		}
	}
}
