package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// WANRejectPrefix is the NFLOG prefix of the rule (without ": ").
const WANRejectPrefix = "WAN-REJECT"

// fw4ChainPost is fw4's include directory for rules appended to a chain.
const fw4ChainPost = "/usr/share/nftables.d/chain-post"

// Fw4SnippetPath is where the rule is installed on OpenWrt: fw4 appends it
// to the zone's input chain (input_<zone>) after the zone's accept rules
// and port redirections, right before the jump to the zone's reject/drop
// chain. Only connections the firewall is about to refuse reach it.
func Fw4SnippetPath(zone string) string {
	return fw4ChainPost + "/input_" + zone + "/90-openpicket-wan-reject.nft"
}

// legacyFw4Snippet is the rule of earlier versions (fw4 dstnat chain); it
// logged every connection no DNAT took, accepted ones included.
const legacyFw4Snippet = fw4ChainPost + "/dstnat/90-openpicket-log-miss.nft"

// NflogTable holds the rule on hosts without fw4.
const NflogTable = "openpicket_nflog"

// WANReject installs the rule logging new WAN connections the firewall
// refuses (NFLOG group 100, prefix "WAN-REJECT: "): port scans and probes
// of closed or filtered ports. Accepted connections (services open on the
// WAN, port forwards) are not logged.
type WANReject struct {
	Host *Host
	// Mode is fw4 or nftables.
	Mode string
	// WAN interfaces (nftables mode; with fw4 the zone selects them).
	WAN []string
	// Zone is the fw4 zone of the WAN (default "wan").
	Zone  string
	Rate  string
	Burst int
	Group int
	// IgnorePorts are destination ports never logged (TCP and UDP).
	IgnorePorts []uint16

	// noSocket is set when the kernel lacks nft_socket (nftables mode).
	noSocket bool
}

func (w *WANReject) zone() string {
	if w.Zone == "" {
		return "wan"
	}
	return w.Zone
}

// rule is the log rule; match goes before the protocol check.
func (w *WANReject) rule(match string) string {
	ignore := ""
	if len(w.IgnorePorts) > 0 {
		ports := slices.Clone(w.IgnorePorts)
		slices.Sort(ports)
		s := make([]string, len(ports))
		for i, p := range ports {
			s[i] = fmt.Sprint(p)
		}
		ignore = "th dport != { " + strings.Join(s, ", ") + " } "
	}
	return fmt.Sprintf(`%smeta l4proto { tcp, udp } %sct state new limit rate %s burst %d packets log group %d prefix "%s: " snaplen 128 counter comment "%s"`,
		match, ignore, w.Rate, w.Burst, w.Group, WANRejectPrefix, w.tag())
}

// tag identifies the rendered configuration, so Ensure notices changes.
func (w *WANReject) tag() string {
	h := sha256.Sum256([]byte(fmt.Sprint(w.Mode, w.WAN, w.zone(), w.Rate, w.Burst, w.Group, w.IgnorePorts, w.noSocket)))
	return "openpicket-wan-reject " + hex.EncodeToString(h[:4])
}

// Fw4Snippet is the content of the fw4 chain-post snippet. Both address
// families pass through the zone's input chain.
func (w *WANReject) Fw4Snippet() string {
	return "# Managed by openpicket-agent: logs new WAN connections the firewall refuses.\n" + w.rule("") + "\n"
}

// Table is the nft script of the standalone table (no fw4). It cannot see
// the verdict of the host's firewall, so it logs connections addressed to
// the node that no DNAT took and no local socket listens for (nft_socket):
// probes of closed ports. Services open on the WAN are left out.
func (w *WANReject) Table() string {
	var b strings.Builder
	b.WriteString("\tchain wan_reject {\n\t\ttype filter hook prerouting priority dstnat + 10; policy accept;\n")
	// Cheap checks first: only new WAN connections to the node itself that
	// no DNAT took go on to the socket lookup.
	fmt.Fprintf(&b, "\t\tiifname != %s return\n", quoteSet(w.WAN))
	b.WriteString("\t\tct state != new return\n\t\tct status dnat return\n\t\tfib daddr type != local return\n")
	if !w.noSocket {
		// A listening socket means an open service: not a probe.
		b.WriteString("\t\tsocket transparent 0 return\n\t\tsocket transparent 1 return\n")
	}
	fmt.Fprintf(&b, "\t\t%s\n\t}\n", w.rule(""))
	return replaceTable("inet", NflogTable, b.String())
}

// Ensure installs the rule if it is missing or outdated.
func (w *WANReject) Ensure(ctx context.Context) error {
	switch w.Mode {
	case "fw4":
		return w.ensureFw4(ctx)
	case "nftables":
		out, err := w.Host.Output(ctx, "list", "table", "inet", NflogTable)
		if err == nil && strings.Contains(string(out), w.tag()) {
			return nil
		}
		err = w.Host.Apply(ctx, w.Table())
		if err != nil && !w.noSocket {
			// Kernels without nft_socket: log without the listener check.
			w.noSocket = true
			if err2 := w.Host.Apply(ctx, w.Table()); err2 == nil {
				return fmt.Errorf("nft_socket unavailable (%v): connections to services open on the WAN are logged too; list them in openpicket.nflog.ignore_ports", err)
			}
			w.noSocket = false
		}
		return err
	}
	return fmt.Errorf("nflog rule: unknown mode %q", w.Mode)
}

func (w *WANReject) ensureFw4(ctx context.Context) error {
	reload := false
	// Earlier versions logged in dstnat, accepted connections included.
	removed, err := w.Host.RemoveFile(legacyFw4Snippet)
	if err != nil {
		return err
	}
	reload = reload || removed
	chain := "input_" + w.zone()
	out, listErr := w.Host.Output(ctx, "list", "chain", "inet", "fw4", chain)
	if listErr == nil && strings.Contains(string(out), "jump accept_from_"+w.zone()) {
		// The zone accepts every input: the rule would log accepted
		// connections. Leave it out.
		removed, err := w.Host.RemoveFile(Fw4SnippetPath(w.zone()))
		if err != nil {
			return err
		}
		if removed || reload {
			if err := w.fw4Reload(ctx); err != nil {
				return err
			}
		}
		return fmt.Errorf("fw4 zone %q accepts all input: WAN-REJECT logging is disabled", w.zone())
	}
	changed, err := w.Host.WriteFile(Fw4SnippetPath(w.zone()), []byte(w.Fw4Snippet()))
	if err != nil {
		return err
	}
	// No chain yet (fw4 not started, or a zone of another name): a reload
	// installs it or reports the problem.
	present := listErr == nil && strings.Contains(string(out), w.tag())
	if changed || reload || !present {
		if err := w.fw4Reload(ctx); err != nil {
			return err
		}
		if listErr != nil {
			if _, err := w.Host.Output(ctx, "list", "chain", "inet", "fw4", chain); err != nil {
				return fmt.Errorf("fw4 has no chain %s: set openpicket.nflog.fw4_zone to the WAN zone", chain)
			}
		}
	}
	return nil
}

func (w *WANReject) fw4Reload(ctx context.Context) error {
	if _, err := w.Host.Exec.Run(ctx, "fw4", []string{"reload"}, nil); err != nil {
		return fmt.Errorf("fw4 reload: %w", err)
	}
	return nil
}

// Remove uninstalls the rule.
func (w *WANReject) Remove(ctx context.Context) error {
	if w.Mode == "fw4" {
		removed, err := w.Host.RemoveFile(Fw4SnippetPath(w.zone()))
		if err != nil {
			return err
		}
		legacy, err := w.Host.RemoveFile(legacyFw4Snippet)
		if err != nil || !(removed || legacy) {
			return err
		}
		return w.fw4Reload(ctx)
	}
	return w.Host.Apply(ctx, deleteTable("inet", NflogTable))
}
