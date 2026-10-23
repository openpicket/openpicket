package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestBuiltin(t *testing.T) {
	items, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, it := range items {
		names[it.Type+" "+it.Name] = true
	}
	for _, want := range []string{"parsers openpicket/suricata-eve", "parsers crowdsecurity/syslog-logs", "scenarios openpicket/compromised-host",
		"scenarios openpicket/wan-reject-portscan", "parsers crowdsecurity/whitelists"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
}

// TestBuiltinSum: a change to the built-in content needs a new
// BuiltinRevision (and builtin.sum updated to the printed value).
func TestBuiltinSum(t *testing.T) {
	h := sha256.New()
	err := fs.WalkDir(content, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := content.ReadFile(p)
		fmt.Fprintf(h, "%s\x00%d\x00", p, len(b))
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%d %s", BuiltinRevision, hex.EncodeToString(h.Sum(nil)))
	got, _ := os.ReadFile("builtin.sum")
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("built-in content changed: bump BuiltinRevision if the content changed, then write to hub/builtin.sum:\n%s", want)
	}
}
