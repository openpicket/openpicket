package enforcer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/platform"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
)

type recExec struct {
	mu      sync.Mutex
	scripts []string
	fail    bool
}

func (r *recExec) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(args) > 0 && args[0] == "list" {
		return []byte("chain guard { iifname != @wan accept; ip saddr @both4 }"), nil
	}
	if r.fail {
		return nil, errors.New("nft: No such file or directory")
	}
	r.scripts = append(r.scripts, string(stdin))
	return nil, nil
}
func (r *recExec) LookPath(n string) (string, error) { return n, nil }

func (r *recExec) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.scripts) == 0 {
		return ""
	}
	return r.scripts[len(r.scripts)-1]
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newEnforcer(t *testing.T, ex platform.Exec, c *clock) *Enforcer {
	t.Helper()
	nets, _ := direction.NewNets([]string{"192.168.1.0/24", "2001:db8:10::/48"})
	return New(Config{
		Host: &nft.Host{Exec: ex}, Table: nft.BanConfig{WAN: nft.NewWAN("wan"), Egress: true},
		Allow:     func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
		Nets:      func() *direction.Nets { return nets },
		StateFile: filepath.Join(t.TempDir(), "decisions.json"), Now: c.now, MaxElements: 100,
	})
}

func ip(v string, ttl time.Duration, both bool) *dataplanev1.Decision {
	d := &dataplanev1.Decision{Value: v, Scope: dataplanev1.Scope_SCOPE_IP, TtlMs: ttl.Milliseconds(), Direction: dataplanev1.Direction_DIRECTION_INBOUND, Origin: "crowdsec"}
	if both {
		d.Direction = dataplanev1.Direction_DIRECTION_BOTH
	}
	return d
}

func rng(v string, ttl time.Duration) *dataplanev1.Decision {
	return &dataplanev1.Decision{Value: v, Scope: dataplanev1.Scope_SCOPE_RANGE, TtlMs: ttl.Milliseconds(), Direction: dataplanev1.Direction_DIRECTION_INBOUND}
}

func TestLocalPolicyRefuses(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	e := newEnforcer(t, ex, c)
	if err := e.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	size, err := e.ApplySnapshot(context.Background(), &dataplanev1.DecisionSnapshot{Version: 5, Decisions: []*dataplanev1.Decision{
		ip("198.51.100.4", time.Hour, false),
		ip("::ffff:198.51.100.9", time.Hour, true), // mapped: normalized
		ip("192.168.1.50", time.Hour, false),       // local network
		ip("10.1.2.3", time.Hour, false),           // allowlist
		ip("2001:db8:10::5", time.Hour, false),     // local IPv6 (GUA)
		rng("0.0.0.0/1", time.Hour),                // too wide
		rng("203.0.113.0/24", time.Hour),
		rng("203.0.113.128/25", time.Hour), // inside the /24, same deadline: one element
		ip("bogus", time.Hour, false),
		ip("198.51.100.30", 0, false), // expired
	}})
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 || e.Version() != 5 {
		t.Fatalf("size=%d version=%d applied=%v", size, e.Version(), e.applied)
	}
	st := e.Status()
	if st.Rejected != 6 || st.BanInV4 != 3 || st.BanBothV4 != 1 || len(st.Refused) != 6 {
		t.Fatalf("status = %+v", st)
	}
	s := ex.last()
	for _, want := range []string{"add element inet openpicket_ban in4 { 198.51.100.4 timeout 3600s }", "both4 { 198.51.100.9 timeout 3600s }", "in4r { 203.0.113.0/24 timeout 3600s }"} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
}

// Re-applying the same decisions later sends nothing: the deadlines did not
// move. A delta from another version is refused.
func TestNoExtensionAndVersionCheck(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	e := newEnforcer(t, ex, c)
	_ = e.Restore(context.Background())
	snap := &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{ip("198.51.100.4", time.Hour, false)}}
	if _, err := e.ApplySnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	n := len(ex.scripts)
	c.t = c.t.Add(10 * time.Minute)
	// The manager resends with the remaining TTL (50 minutes).
	snap2 := &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{ip("198.51.100.4", 50*time.Minute, false)}}
	if _, err := e.ApplySnapshot(context.Background(), snap2); err != nil {
		t.Fatal(err)
	}
	if len(ex.scripts) != n {
		t.Fatalf("unchanged decision rewritten: %q", ex.last())
	}
	// LAPI extended the decision: replaced with the new remaining time.
	if _, err := e.ApplyDelta(context.Background(), &dataplanev1.DecisionDelta{FromVersion: 1, ToVersion: 2,
		Upserts: []*dataplanev1.Decision{ip("198.51.100.4", 3*time.Hour, false)}}); err != nil {
		t.Fatal(err)
	}
	if s := ex.last(); !strings.Contains(s, "delete element inet openpicket_ban in4 { 198.51.100.4 }") || !strings.Contains(s, "198.51.100.4 timeout 10800s") {
		t.Fatalf("extension script:\n%s", s)
	}
	if _, err := e.ApplyDelta(context.Background(), &dataplanev1.DecisionDelta{FromVersion: 7, ToVersion: 8}); !errors.Is(err, dataplane.ErrVersionMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	// Direction change moves the value between sets.
	if _, err := e.ApplyDelta(context.Background(), &dataplanev1.DecisionDelta{FromVersion: 2, ToVersion: 3,
		Upserts: []*dataplanev1.Decision{ip("198.51.100.4", 3*time.Hour, true)}}); err != nil {
		t.Fatal(err)
	}
	if s := ex.last(); !strings.Contains(s, "delete element inet openpicket_ban in4 { 198.51.100.4 }") || !strings.Contains(s, "both4 { 198.51.100.4 timeout") {
		t.Fatalf("direction change script:\n%s", s)
	}
	if _, err := e.ApplyDelta(context.Background(), &dataplanev1.DecisionDelta{FromVersion: 3, ToVersion: 4, Deletes: []string{"198.51.100.4"}}); err != nil {
		t.Fatal(err)
	}
	if s := ex.last(); !strings.Contains(s, "delete element inet openpicket_ban both4 { 198.51.100.4 }") || e.Status().BanBothV4 != 0 {
		t.Fatalf("delete script:\n%s", s)
	}
}

func TestRestore(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	e := newEnforcer(t, ex, c)
	_ = e.Restore(context.Background())
	_, _ = e.ApplySnapshot(context.Background(), &dataplanev1.DecisionSnapshot{Version: 9, Decisions: []*dataplanev1.Decision{
		ip("198.51.100.4", 4*time.Hour, false), ip("198.51.100.5", 10*time.Minute, false)}})
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}

	// Reboot 30 minutes later with a correct clock: deadlines kept, the
	// expired block is not restored, the version continues.
	c2 := &clock{t: c.t.Add(30 * time.Minute)}
	ex2 := &recExec{}
	e2 := newEnforcer(t, ex2, c2)
	e2.cfg.StateFile = e.cfg.StateFile
	if err := e2.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e2.Version() != 9 || len(e2.decisions) != 1 || !strings.Contains(ex2.last(), "198.51.100.4 timeout 12600s") {
		t.Fatalf("restore: version=%d decisions=%v script=%q", e2.Version(), e2.decisions, ex2.last())
	}

	// Reboot of a router without RTC: the clock is before the save time.
	c3 := &clock{t: time.Unix(1_700_000_000, 0)}
	ex3 := &recExec{}
	e3 := newEnforcer(t, ex3, c3)
	e3.cfg.StateFile = e.cfg.StateFile
	if err := e3.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e3.Version() != 0 || !strings.Contains(ex3.last(), "198.51.100.4 timeout 3600s") || !strings.Contains(ex3.last(), "198.51.100.5 timeout 600s") {
		t.Fatalf("untrusted restore: version=%d script=%q", e3.Version(), ex3.last())
	}
}

func TestCapKeepsManualFirst(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	e := newEnforcer(t, &recExec{}, c)
	e.cfg.MaxElements = 2
	_ = e.Restore(context.Background())
	manual := ip("198.51.100.1", time.Minute, false)
	manual.Origin = "manual"
	_, _ = e.ApplySnapshot(context.Background(), &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		ip("198.51.100.2", time.Hour, false), ip("198.51.100.3", 2*time.Hour, false), manual}})
	if _, ok := e.applied["198.51.100.1"]; !ok || len(e.applied) != 2 {
		t.Fatalf("applied = %v", e.applied)
	}
	if _, ok := e.applied["198.51.100.3"]; !ok {
		t.Fatal("longest crowdsec decision should be kept")
	}
}

// TestStatusReportsLocalReasonsFirst: the report is capped, and the
// element limit can refuse thousands of decisions; the few local reasons
// must still be in it.
func TestStatusReportsLocalReasonsFirst(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	e := newEnforcer(t, &recExec{}, c)
	e.cfg.MaxElements = 1
	_ = e.Restore(context.Background())
	ds := []*dataplanev1.Decision{ip("192.168.1.50", time.Hour, false)}
	for i := range maxRefusedReported + 10 {
		ds = append(ds, ip(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1), time.Hour, false))
	}
	_, _ = e.ApplySnapshot(context.Background(), &dataplanev1.DecisionSnapshot{Version: 1, Decisions: ds})
	st := e.Status()
	if st.Rejected != uint64(maxRefusedReported+10) || len(st.Refused) != maxRefusedReported {
		t.Fatalf("rejected=%d listed=%d", st.Rejected, len(st.Refused))
	}
	if r := st.Refused[0]; r.Value != "192.168.1.50" || !strings.Contains(r.Reason, "local network") {
		t.Fatalf("first = %v", r)
	}
	if r := st.Refused[1]; !strings.HasPrefix(r.Reason, reasonLimit) {
		t.Fatalf("second = %v", r)
	}
}

// TestNetnsResync runs on a real kernel (scripts/netns-test.sh): an element
// that expired by itself makes the delete fail; the enforcer reads the sets
// back and converges.
func TestNetnsResync(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	c := &clock{t: time.Now()}
	e := newEnforcer(t, platform.LocalExec{}, c)
	ctx := context.Background()
	if err := e.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		ip("198.51.100.4", 2*time.Second, false), ip("198.51.100.5", time.Hour, true)}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // 198.51.100.4 expires in the kernel
	// The enforcer still believes .4 is live (its clock did not move) and
	// deletes it: the kernel refuses, the enforcer resyncs.
	if _, err := e.ApplyDelta(ctx, &dataplanev1.DecisionDelta{FromVersion: 1, ToVersion: 2, Deletes: []string{"198.51.100.4"},
		Upserts: []*dataplanev1.Decision{ip("198.51.100.6", time.Hour, false)}}); err != nil {
		t.Fatal(err)
	}
	in4, _ := e.cfg.Host.ListElements(ctx, "in4")
	both4, _ := e.cfg.Host.ListElements(ctx, "both4")
	if _, ok := in4["198.51.100.6"]; !ok || len(in4) != 1 || len(both4) != 1 {
		t.Fatalf("in4=%v both4=%v", in4, both4)
	}
	// The table is removed behind our back: Ensure rebuilds it with the
	// remaining times.
	if err := e.cfg.Host.Apply(ctx, "delete table inet openpicket_ban\n"); err != nil {
		t.Fatal(err)
	}
	if err := e.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	in4, _ = e.cfg.Host.ListElements(ctx, "in4")
	if exp, ok := in4["198.51.100.6"]; !ok || exp > time.Hour {
		t.Fatalf("after rebuild in4=%v", in4)
	}
}

func TestNestedRangeOutlivesOuter(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	e := newEnforcer(t, ex, c)
	ctx := context.Background()
	_ = e.Restore(ctx)
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		rng("198.51.100.0/24", time.Minute), rng("198.51.100.0/25", time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	s := ex.last()
	for _, want := range []string{"198.51.100.0/25 timeout 3600s", "198.51.100.128/25 timeout 60s"} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "198.51.100.0/24") || len(e.decisions) != 2 {
		t.Fatalf("the outer range must be split, both decisions kept:\n%s\n%v", s, e.decisions)
	}
	// The /24 expires: the /25 stays blocked.
	c.t = c.t.Add(2 * time.Minute)
	if err := e.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if en, ok := e.applied["198.51.100.0/25"]; !ok || en.Deadline.Sub(c.t) < 50*time.Minute {
		t.Fatalf("inner range lost after the outer expired: %v", e.applied)
	}
}

func TestDeletingOuterRangeRestoresInner(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	e := newEnforcer(t, ex, c)
	ctx := context.Background()
	_ = e.Restore(ctx)
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		rng("198.51.100.0/24", 2*time.Hour), rng("198.51.100.0/25", time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if len(e.applied) != 1 {
		t.Fatalf("a shorter inner range is covered: %v", e.applied)
	}
	if _, err := e.ApplyDelta(ctx, &dataplanev1.DecisionDelta{FromVersion: 1, ToVersion: 2, Deletes: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	s := ex.last()
	if !strings.Contains(s, "delete element inet openpicket_ban in4r { 198.51.100.0/24 }") || !strings.Contains(s, "198.51.100.0/25 timeout 3600s") {
		t.Fatalf("inner range not restored:\n%s", s)
	}
}

func TestLocalNetworksAndAllowlistChanges(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	nets1, _ := direction.NewNets([]string{"192.168.1.0/24"})
	nets2, _ := direction.NewNets([]string{"192.168.1.0/24", "100.64.0.0/10"})
	var mu sync.Mutex
	nets, allow := nets1, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	state := filepath.Join(t.TempDir(), "d.json")
	mk := func() *Enforcer {
		return New(Config{Host: &nft.Host{Exec: ex}, Table: nft.BanConfig{WAN: nft.NewWAN("wan")}, StateFile: state, Now: c.now,
			Nets:  func() *direction.Nets { mu.Lock(); defer mu.Unlock(); return nets },
			Allow: func() []netip.Prefix { mu.Lock(); defer mu.Unlock(); return allow }})
	}
	set := func(n *direction.Nets, a []netip.Prefix) {
		mu.Lock()
		nets, allow = n, a
		mu.Unlock()
	}
	e := mk()
	ctx := context.Background()
	_ = e.Restore(ctx)
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		ip("100.64.5.9", time.Hour, false), ip("10.1.2.3", time.Hour, false)}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.applied["100.64.5.9"]; !ok {
		t.Fatal("not applied")
	}
	// The address becomes local (DHCP, HOME_NET): unblocked, kept.
	set(nets2, allow)
	if err := e.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.applied["100.64.5.9"]; ok || !strings.Contains(ex.last(), "delete element inet openpicket_ban in4 { 100.64.5.9 }") {
		t.Fatalf("local address still blocked: %v\n%s", e.applied, ex.last())
	}
	st := e.Status()
	if st.Rejected != 2 || !strings.Contains(st.Refused[0].Reason+st.Refused[1].Reason, "local network (100.64.0.0/10)") {
		t.Fatalf("status: %v", st)
	}
	// A restore while it is local does not block it either.
	_ = e.Save()
	e2 := mk()
	if err := e2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := e2.applied["100.64.5.9"]; ok || len(e2.decisions) != 2 {
		t.Fatalf("restore: applied %v decisions %v", e2.applied, e2.decisions)
	}
	// Not local any more, and out of the allowlist: both blocked again.
	set(nets1, nil)
	if err := e2.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	_, a := e2.applied["100.64.5.9"]
	_, b := e2.applied["10.1.2.3"]
	if !a || !b || e2.Status().Rejected != 0 {
		t.Fatalf("not blocked again: %v", e2.applied)
	}
}

// TestNetnsNestedRanges checks on a real kernel that splitting a range
// (delete + add pieces in one transaction) is accepted by the interval set
// and that the inner range outlives the outer one's timeout.
func TestNetnsNestedRanges(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	_ = exec.Command("nft", "flush", "ruleset").Run()
	c := &clock{t: time.Now()}
	e := newEnforcer(t, platform.LocalExec{}, c)
	ctx := context.Background()
	if err := e.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		rng("203.0.113.0/24", 2*time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	// A shorter outer range arrives around a longer inner one: the /24 is
	// replaced by pieces in the same transaction.
	if _, err := e.ApplyDelta(ctx, &dataplanev1.DecisionDelta{FromVersion: 1, ToVersion: 2, Upserts: []*dataplanev1.Decision{
		rng("203.0.113.0/24", 2*time.Second), rng("203.0.113.64/26", time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	in4r, err := e.cfg.Host.ListElements(ctx, "in4r")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := in4r["203.0.113.64/26"]; !ok || len(in4r) != 3 {
		t.Fatalf("pieces: %v", in4r)
	}
	time.Sleep(3 * time.Second) // the outer pieces expire in the kernel
	in4r, _ = e.cfg.Host.ListElements(ctx, "in4r")
	if exp, ok := in4r["203.0.113.64/26"]; !ok || len(in4r) != 1 || exp < 50*time.Minute {
		t.Fatalf("after the outer range expired: %v", in4r)
	}
}

// TestWANChange: a new WAN list (fw4 zone devices) replaces the wan set
// only; the bans and their timeouts are not touched. A table of an earlier
// version (no wan set) is recreated.
func TestWANChange(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	ex := &recExec{}
	wan := nft.NewWAN("wan")
	e := New(Config{Host: &nft.Host{Exec: ex}, Table: nft.BanConfig{WAN: wan}, Now: c.now, MaxElements: 100})
	ctx := context.Background()
	_ = e.Restore(ctx)
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{ip("198.51.100.4", time.Hour, false)}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ex.scripts[0], `elements = { "wan" }`) {
		t.Fatalf("table:\n%s", ex.scripts[0])
	}
	n := len(ex.scripts)
	if err := e.Ensure(ctx); err != nil || len(ex.scripts) != n {
		t.Fatalf("nothing changed, yet %d scripts: %v", len(ex.scripts)-n, err)
	}
	wan.Set([]string{"pppoe-wan", "wwan0"})
	if err := e.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ex.last(); got != nft.WANScript([]string{"pppoe-wan", "wwan0"}) || len(ex.scripts) != n+1 {
		t.Fatalf("WAN change applied %d scripts, last:\n%s", len(ex.scripts)-n, got)
	}
}
