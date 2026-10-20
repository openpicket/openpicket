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

func TestDNATMissFw4(t *testing.T) {
	root := t.TempDir()
	ex := &fakeExec{listing: map[string]string{}}
	d := &DNATMiss{Host: &Host{Exec: ex, FS: platform.HostFS{Root: root}}, Mode: "fw4", WAN: []string{"wan"}, Rate: "30/minute", Burst: 10, Group: 100}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, Fw4SnippetPath))
	if err != nil {
		t.Fatal(err)
	}
	want := `iifname { "wan" } meta nfproto ipv4 meta l4proto { tcp, udp } ct state new limit rate 30/minute burst 10 packets log group 100 prefix "DNAT-MISS: " snaplen 128 counter`
	if !strings.Contains(string(b), want) || ex.count("fw4 reload") != 1 {
		t.Fatalf("snippet %q, reloads %d", b, ex.count("fw4 reload"))
	}
	// Unchanged file and rule present: no reload.
	ex.listing["list chain inet fw4 dstnat"] = `chain dstnat { ... log group 100 prefix "DNAT-MISS: " }`
	if err := d.Ensure(context.Background()); err != nil || ex.count("fw4 reload") != 1 {
		t.Fatalf("second ensure: %v, reloads %d", err, ex.count("fw4 reload"))
	}
	// fw4 lost the rule (e.g. a manual reload with a removed file): reload.
	delete(ex.listing, "list chain inet fw4 dstnat")
	if err := d.Ensure(context.Background()); err != nil || ex.count("fw4 reload") != 2 {
		t.Fatalf("third ensure: %v, reloads %d", err, ex.count("fw4 reload"))
	}
	if err := d.Remove(context.Background()); err != nil || ex.count("fw4 reload") != 3 {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, Fw4SnippetPath)); !os.IsNotExist(err) {
		t.Fatal("snippet not removed")
	}
}

func TestDNATMissTable(t *testing.T) {
	ex := &fakeExec{listing: map[string]string{}}
	d := &DNATMiss{Host: &Host{Exec: ex}, Mode: "nftables", WAN: []string{"eth0", "ppp0"}, Rate: "30/minute", Burst: 10, Group: 100}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := ex.scripts[0]
	for _, want := range []string{
		"table inet openpicket_nflog\ndelete table inet openpicket_nflog\n",
		"type filter hook prerouting priority dstnat + 10; policy accept;",
		`iifname { "eth0", "ppp0" } ct status != dnat fib daddr type local meta l4proto { tcp, udp } ct state new`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	ex.listing["list table inet openpicket_nflog"] = s
	if err := d.Ensure(context.Background()); err != nil || len(ex.scripts) != 1 {
		t.Fatal("present table must not be reapplied")
	}
}
