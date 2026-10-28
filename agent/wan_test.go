package agent

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	suricfg "github.com/jc-lab/suricontroller/agent/config"

	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/nft"
)

type fw4Exec struct{ input string }

func (f *fw4Exec) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, error) {
	if strings.Join(args, " ") == "list chain inet fw4 input" && f.input != "" {
		return []byte(f.input), nil
	}
	return nil, errors.New("No such file or directory")
}
func (f *fw4Exec) LookPath(n string) (string, error) { return n, nil }

func fw4Input(rules ...string) string {
	return "table inet fw4 {\n\tchain input {\n\t\t" + strings.Join(rules, "\n\t\t") + "\n\t}\n}"
}

func TestRefreshWAN(t *testing.T) {
	ex := &fw4Exec{input: fw4Input(`iifname "br-lan" jump input_lan`, `iifname { "eth1", "pppoe-wan" } jump input_wan`, `iifname "wwan0" jump input_lte`)}
	cfg := &config.Config{Suri: &suricfg.Config{}, Node: config.Node{StateDir: t.TempDir()}}
	cfg.OpenPicket.WANInterfaces = []string{"wg0"}
	cfg.OpenPicket.Fw4Zones = []string{"wan", "lte"}
	exists := map[string]bool{"eth1": true, "pppoe-wan": true, "wwan0": true, "wg0": true}
	orig := ifaceExists
	ifaceExists = func(n string) bool { return exists[n] }
	t.Cleanup(func() { ifaceExists = orig })
	a := &Agent{cfg: cfg, log: slog.New(slog.DiscardHandler), host: &nft.Host{Exec: ex}, fw4: true, wan: nft.NewWAN("wg0")}
	ctx := context.Background()
	if !a.refreshWAN(ctx) || !slices.Equal(a.wan.Get(), []string{"eth1", "pppoe-wan", "wg0", "wwan0"}) {
		t.Fatalf("wan = %v", a.wan.Get())
	}
	if a.refreshWAN(ctx) {
		t.Fatal("no change reported as one")
	}
	// PPPoE down: fw4 drops the device, which no longer exists. It stays,
	// so bans apply as soon as the link is back.
	delete(exists, "pppoe-wan")
	ex.input = fw4Input(`iifname "eth1" jump input_wan`, `iifname "wwan0" jump input_lte`)
	if a.refreshWAN(ctx) || !slices.Contains(a.wan.Get(), "pppoe-wan") {
		t.Fatalf("down device dropped: %v", a.wan.Get())
	}
	// The LTE modem moved to another zone (it exists): no longer a WAN.
	ex.input = fw4Input(`iifname "eth1" jump input_wan`, `iifname "wwan0" jump input_lan`)
	if !a.refreshWAN(ctx) || slices.Contains(a.wan.Get(), "wwan0") {
		t.Fatalf("moved device kept: %v", a.wan.Get())
	}
	// fw4 reloading (no table): the list stays.
	ex.input = ""
	if a.refreshWAN(ctx) || len(a.wan.Get()) != 3 {
		t.Fatalf("lost the WAN while fw4 reloads: %v", a.wan.Get())
	}
	// Saved for the next boot, when fw4 may not be loaded yet.
	if got := a.loadZoneDevices(); !slices.Equal(got, []string{"eth1", "pppoe-wan"}) {
		t.Fatalf("saved = %v", got)
	}
}
