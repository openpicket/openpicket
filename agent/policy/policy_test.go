package policy

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

type recExec struct {
	mu      sync.Mutex
	scripts []string
	present bool
}

func (r *recExec) Run(_ context.Context, _ string, args []string, stdin []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(args) > 0 && (args[0] == "list" || args[0] == "-j") {
		if !r.present {
			return nil, context.Canceled
		}
		return []byte(`{"nftables":[]}`), nil
	}
	r.scripts = append(r.scripts, string(stdin))
	r.present = !strings.Contains(string(stdin), "delete table inet openpicket_policy\n") || strings.Contains(string(stdin), "chain dispatch")
	return nil, nil
}
func (r *recExec) LookPath(n string) (string, error) { return n, nil }

func bundle(v uint64) *dataplanev1.PolicyBundle {
	return &dataplanev1.PolicyBundle{Version: v,
		Sets: []*dataplanev1.NamedSet{{Id: "p_r0", Cidrs: []string{"1.0.0.0/24"}}},
		Policies: []*dataplanev1.PortPolicy{{Id: "p", Mode: dataplanev1.PolicyMode_POLICY_MODE_ENFORCE, Proto: dataplanev1.L4Proto_L4_PROTO_TCP,
			Ports: []*dataplanev1.PortRange{{From: 443, To: 443}}, DefaultAction: dataplanev1.PolicyAction_POLICY_ACTION_ACCEPT,
			Rules: []*dataplanev1.PolicyRule{{SetId: "p_r0", Action: dataplanev1.PolicyAction_POLICY_ACTION_DROP}}}}}
}

func TestApplyRefuseRestore(t *testing.T) {
	ex := &recExec{}
	state := filepath.Join(t.TempDir(), "policy.pb")
	s := New(Config{Host: &nft.Host{Exec: ex}, Table: nft.PolicyConfig{WAN: nft.NewWAN("wan")}, MaxElements: 10, StateFile: state})
	ctx := context.Background()
	if err := s.Apply(ctx, bundle(4)); err != nil {
		t.Fatal(err)
	}
	if s.Version() != 4 || !strings.Contains(ex.scripts[0], "jump p_p") {
		t.Fatalf("version %d script %q", s.Version(), ex.scripts)
	}
	// A bundle breaking the contract is refused; the previous one stays.
	bad := bundle(5)
	bad.Sets[0].Cidrs = []string{"1.0.0.0/24 } ; flush ruleset ; set x {"}
	if err := s.Apply(ctx, bad); err == nil || s.Version() != 4 || len(ex.scripts) != 1 {
		t.Fatalf("bad bundle: err=%v version=%d scripts=%d", err, s.Version(), len(ex.scripts))
	}
	if st := s.Status(ctx); st.Version != 4 || st.LastError == "" {
		t.Fatalf("status = %+v", st)
	}
	// Boot: the saved bundle comes back before any connection.
	ex2 := &recExec{}
	s2 := New(Config{Host: &nft.Host{Exec: ex2}, Table: nft.PolicyConfig{WAN: nft.NewWAN("wan")}, MaxElements: 10, StateFile: state})
	if err := s2.Restore(ctx); err != nil || s2.Version() != 4 || len(ex2.scripts) != 1 {
		t.Fatalf("restore: %v version=%d", err, s2.Version())
	}
	// The table disappears: Ensure re-applies it.
	ex2.present = false
	if err := s2.Ensure(ctx); err != nil || len(ex2.scripts) != 2 {
		t.Fatalf("ensure: %v scripts=%d", err, len(ex2.scripts))
	}
}
