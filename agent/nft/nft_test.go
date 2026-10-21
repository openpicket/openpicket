package nft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jc-lab/suricontroller/agent/platform"
)

// fakeExec records commands and serves canned "nft list" output.
type fakeExec struct {
	mu      sync.Mutex
	calls   []string
	scripts []string
	listing map[string]string // args joined -> output; missing = error
}

func (f *fakeExec) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if len(stdin) > 0 {
		f.scripts = append(f.scripts, string(stdin))
	}
	if len(args) > 0 && args[0] == "list" {
		if out, ok := f.listing[strings.Join(args, " ")]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("No such file or directory")
	}
	return nil, nil
}
func (f *fakeExec) LookPath(name string) (string, error) { return "/usr/sbin/" + name, nil }

func (f *fakeExec) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestWANRejectFw4(t *testing.T) {
	root := t.TempDir()
	ex := &fakeExec{listing: map[string]string{}}
	host := &Host{Exec: ex, FS: platform.HostFS{Root: root}}
	// An earlier version's dstnat snippet is removed.
	legacy := filepath.Join(root, legacyFw4Snippet)
	_ = os.MkdirAll(filepath.Dir(legacy), 0o755)
	_ = os.WriteFile(legacy, []byte("old"), 0o644)
	w := &WANReject{Host: host, Mode: "fw4", Rate: "30/minute", Burst: 10, Group: 100, IgnorePorts: []uint16{51820, 22}}
	ex.listing["list chain inet fw4 input_wan"] = "chain input_wan {\n\tjump reject_from_wan\n}"
	if err := w.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy dstnat snippet left in place")
	}
	b, err := os.ReadFile(filepath.Join(root, Fw4SnippetPath("wan")))
	if err != nil {
		t.Fatal(err)
	}
	want := `meta l4proto { tcp, udp } th dport != { 22, 51820 } ct state new limit rate 30/minute burst 10 packets log group 100 prefix "WAN-REJECT: " snaplen 128 counter comment "openpicket-wan-reject `
	if !strings.Contains(string(b), want) || strings.Contains(string(b), "iifname") || ex.count("fw4 reload") != 1 {
		t.Fatalf("snippet %q, reloads %d", b, ex.count("fw4 reload"))
	}
	// Unchanged file and rule present: no reload.
	ex.listing["list chain inet fw4 input_wan"] = "chain input_wan {\n\t" + strings.TrimSpace(w.rule("")) + "\n\tjump reject_from_wan\n}"
	if err := w.Ensure(context.Background()); err != nil || ex.count("fw4 reload") != 1 {
		t.Fatalf("second ensure: %v, reloads %d", err, ex.count("fw4 reload"))
	}
	// fw4 lost the rule (e.g. a manual reload with a removed file): reload.
	ex.listing["list chain inet fw4 input_wan"] = "chain input_wan {\n\tjump reject_from_wan\n}"
	if err := w.Ensure(context.Background()); err != nil || ex.count("fw4 reload") != 2 {
		t.Fatalf("third ensure: %v, reloads %d", err, ex.count("fw4 reload"))
	}
	// A zone that accepts all input would log accepted connections.
	ex.listing["list chain inet fw4 input_wan"] = "chain input_wan {\n\tjump accept_from_wan\n}"
	if err := w.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "accepts all input") {
		t.Fatalf("accept zone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, Fw4SnippetPath("wan"))); !os.IsNotExist(err) {
		t.Fatal("snippet left in an accepting zone")
	}
	ex.listing["list chain inet fw4 input_wan"] = "chain input_wan {\n\tjump reject_from_wan\n}"
	if err := w.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	reloads := ex.count("fw4 reload")
	if err := w.Remove(context.Background()); err != nil || ex.count("fw4 reload") != reloads+1 {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, Fw4SnippetPath("wan"))); !os.IsNotExist(err) {
		t.Fatal("snippet not removed")
	}
}

func TestWANRejectFw4UnknownZone(t *testing.T) {
	ex := &fakeExec{listing: map[string]string{}}
	w := &WANReject{Host: &Host{Exec: ex, FS: platform.HostFS{Root: t.TempDir()}}, Mode: "fw4", Zone: "internet", Rate: "30/minute", Burst: 10, Group: 100}
	if err := w.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "fw4_zone") {
		t.Fatalf("unknown zone: %v", err)
	}
}

func TestWANRejectTable(t *testing.T) {
	ex := &fakeExec{listing: map[string]string{}}
	w := &WANReject{Host: &Host{Exec: ex}, Mode: "nftables", WAN: []string{"eth0", "ppp0"}, Rate: "30/minute", Burst: 10, Group: 100}
	if err := w.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := ex.scripts[0]
	for _, want := range []string{
		"table inet openpicket_nflog\ndelete table inet openpicket_nflog\n",
		"type filter hook prerouting priority dstnat + 10; policy accept;",
		`iifname != { "eth0", "ppp0" } return`,
		"ct status dnat return\n\t\tfib daddr type != local return",
		"socket transparent 0 return",
		`log group 100 prefix "WAN-REJECT: "`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	ex.listing["list table inet openpicket_nflog"] = s
	if err := w.Ensure(context.Background()); err != nil || len(ex.scripts) != 1 {
		t.Fatal("present table must not be reapplied")
	}
	// A changed configuration is applied again.
	w.IgnorePorts = []uint16{22}
	if err := w.Ensure(context.Background()); err != nil || len(ex.scripts) != 2 || !strings.Contains(ex.scripts[1], "th dport != { 22 }") {
		t.Fatalf("changed config: %v %d", err, len(ex.scripts))
	}
}
