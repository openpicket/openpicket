package nft

import (
	"context"
	"fmt"
	"strings"
)

// Fw4SnippetPath is where the DNAT-miss rule is installed on OpenWrt: fw4
// appends it to its dstnat chain, after every DNAT rule, so only packets no
// DNAT took are logged.
const Fw4SnippetPath = "/usr/share/nftables.d/chain-post/dstnat/90-openpicket-log-miss.nft"

// NflogTable holds the DNAT-miss rule on hosts without fw4.
const NflogTable = "openpicket_nflog"

// DNATMiss installs the rule logging new WAN connections that no DNAT rule
// took (NFLOG group 100, prefix "DNAT-MISS: ").
type DNATMiss struct {
	Host *Host
	// Mode is fw4 or nftables.
	Mode  string
	WAN   []string
	Rate  string
	Burst int
	Group int
}

// rule is shared by both modes.
func (d *DNATMiss) rule(extra string) string {
	return fmt.Sprintf(`iifname %s %smeta l4proto { tcp, udp } ct state new limit rate %s burst %d packets log group %d prefix "DNAT-MISS: " snaplen 128 counter`,
		quoteSet(d.WAN), extra, d.Rate, d.Burst, d.Group)
}

// Fw4Snippet is the content of the fw4 chain-post snippet.
func (d *DNATMiss) Fw4Snippet() string {
	return "# Managed by openpicket-agent: logs new WAN connections no DNAT rule took.\n" +
		d.rule("meta nfproto ipv4 ") + "\n"
}

// Table is the nft script of the standalone table: after NAT (priority
// dstnat + 10) a connection without the dnat status bit that is addressed
// to the node itself was not forwarded by any DNAT rule.
func (d *DNATMiss) Table() string {
	body := "\tchain dnat_miss {\n\t\ttype filter hook prerouting priority dstnat + 10; policy accept;\n\t\t" +
		d.rule("ct status != dnat fib daddr type local ") + "\n\t}\n"
	return replaceTable("inet", NflogTable, body)
}

// Ensure installs the rule if it is missing or outdated.
func (d *DNATMiss) Ensure(ctx context.Context) error {
	switch d.Mode {
	case "fw4":
		changed, err := d.Host.WriteFile(Fw4SnippetPath, []byte(d.Fw4Snippet()))
		if err != nil {
			return err
		}
		present, err := d.fw4RulePresent(ctx)
		if err != nil {
			return err
		}
		if changed || !present {
			if _, err := d.Host.Exec.Run(ctx, "fw4", []string{"reload"}, nil); err != nil {
				return fmt.Errorf("fw4 reload: %w", err)
			}
		}
		return nil
	case "nftables":
		out, err := d.Host.Output(ctx, "list", "table", "inet", NflogTable)
		if err == nil && strings.Contains(string(out), "DNAT-MISS") && strings.Contains(string(out), d.Rate) {
			return nil
		}
		return d.Host.Apply(ctx, d.Table())
	}
	return fmt.Errorf("nflog rule: unknown mode %q", d.Mode)
}

func (d *DNATMiss) fw4RulePresent(ctx context.Context) (bool, error) {
	out, err := d.Host.Output(ctx, "list", "chain", "inet", "fw4", "dstnat")
	if err != nil {
		// No dstnat chain yet (fw4 not started): a reload installs it.
		return false, nil
	}
	return strings.Contains(string(out), "DNAT-MISS"), nil
}

// Remove uninstalls the rule.
func (d *DNATMiss) Remove(ctx context.Context) error {
	if d.Mode == "fw4" {
		removed, err := d.Host.RemoveFile(Fw4SnippetPath)
		if err != nil || !removed {
			return err
		}
		_, err = d.Host.Exec.Run(ctx, "fw4", []string{"reload"}, nil)
		return err
	}
	return d.Host.Apply(ctx, deleteTable("inet", NflogTable))
}
