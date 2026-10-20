package nft

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// nftCheck validates a script with `nft -c` on a real kernel
// (scripts/nft-check.sh, docker). Enabled by OPENPICKET_TEST_NFT=1.
func nftCheck(t *testing.T, script string) {
	t.Helper()
	if os.Getenv("OPENPICKET_TEST_NFT") != "1" {
		t.Skip("OPENPICKET_TEST_NFT not set")
	}
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command(filepath.Join(filepath.Dir(file), "..", "..", "scripts", "nft-check.sh"))
	cmd.Stdin = bytes.NewBufferString(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected the script: %v\n%s\n--- script ---\n%s", err, out, script)
	}
}

func TestKernelAcceptsDNATMiss(t *testing.T) {
	d := &DNATMiss{WAN: []string{"eth0", "pppoe-wan"}, Rate: "30/minute", Burst: 10, Group: 100}
	nftCheck(t, d.Table())
	// The fw4 snippet goes into fw4's nat dstnat chain.
	nftCheck(t, "table inet fw4 {\n\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\t"+d.Fw4Snippet()+"\t}\n}\n")
}
