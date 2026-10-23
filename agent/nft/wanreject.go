package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	return fw4ChainPost + "/input_" + zone + "/" + fw4SnippetName
}

const fw4SnippetName = "90-openpicket-wan-reject.nft"

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
	// WAN interfaces (nftables mode; with fw4 the zones select them).
	WAN *WAN
	// Zones are the fw4 zones facing the internet.
	Zones []string
	Rate  string
	Burst int
	Group int
	// IgnorePorts are destination ports never logged (TCP and UDP).
	IgnorePorts []uint16
	// WithoutSocketCheck allows the nftables rule without its listener
	// check when the kernel lacks nft_socket. Connections to services open
	// on the WAN are then logged unless their ports are in IgnorePorts, and
	// the scenarios would ban their users; the rule is left out otherwise.
	WithoutSocketCheck bool

	// noSocket is set when the kernel lacks nft_socket (nftables mode).
	noSocket bool

	mu      sync.Mutex
	lastErr string
}

// ErrNoSocket: the kernel lacks nft_socket and WithoutSocketCheck is off.
var ErrNoSocket = errors.New("nft_socket unavailable: WAN-REJECT logging is off, since it would also log connections to services open on the WAN " +
	"(load the nft_socket module, or set openpicket.nflog.without_socket_check and list those services in ignore_ports)")

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
	var wan []string
	if w.Mode != "fw4" {
		// With fw4 the zones select the devices: a WAN change must not
		// rewrite the snippets and reload fw4.
		wan = w.WAN.Get()
	}
	h := sha256.Sum256([]byte(fmt.Sprint(w.Mode, wan, w.Zones, w.Rate, w.Burst, w.Group, w.IgnorePorts, w.noSocket)))
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
	fmt.Fprintf(&b, "\t\t%sreturn\n", notWAN("iifname", w.WAN.Get()))
	b.WriteString("\t\tct state != new return\n\t\tct status dnat return\n\t\tfib daddr type != local return\n")
	if !w.noSocket {
		// A listening socket means an open service: not a probe.
		b.WriteString("\t\tsocket transparent 0 return\n\t\tsocket transparent 1 return\n")
	}
	fmt.Fprintf(&b, "\t\t%s\n\t}\n", w.rule(""))
	return replaceTable("inet", NflogTable, b.String())
}

// Ensure installs the rule if it is missing or outdated. Its error is
// also kept for the status report (Err).
func (w *WANReject) Ensure(ctx context.Context) error {
	var err error
	switch w.Mode {
	case "fw4":
		err = w.ensureFw4(ctx)
	case "nftables":
		err = w.ensureTable(ctx)
	default:
		err = fmt.Errorf("nflog rule: unknown mode %q", w.Mode)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastErr = ""
	if err != nil {
		w.lastErr = err.Error()
	}
	return err
}

// Err is why the rule is not installed (or not everywhere), "" when it is.
func (w *WANReject) Err() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *WANReject) ensureTable(ctx context.Context) error {
	out, err := w.Host.Output(ctx, "list", "table", "inet", NflogTable)
	if err == nil && strings.Contains(string(out), w.tag()) {
		return nil
	}
	w.noSocket = false
	err = w.Host.Apply(ctx, w.Table())
	if err == nil {
		return nil
	}
	// Is nft_socket the problem? The rule without it must then be valid.
	w.noSocket = true
	if w.Host.Check(ctx, w.Table()) != nil {
		w.noSocket = false
		return err
	}
	if !w.WithoutSocketCheck {
		w.noSocket = false
		if rerr := w.Host.Apply(ctx, deleteTable("inet", NflogTable)); rerr != nil {
			return errors.Join(ErrNoSocket, rerr)
		}
		return ErrNoSocket
	}
	return w.Host.Apply(ctx, w.Table())
}

func (w *WANReject) ensureFw4(ctx context.Context) error {
	// Earlier versions logged in dstnat, accepted connections included;
	// zones no longer listed keep no rule.
	reload, err := w.removeSnippets(w.Zones)
	if err != nil {
		return err
	}
	var (
		errs    []error
		missing []string
	)
	for _, zone := range w.Zones {
		chain := "input_" + zone
		out, listErr := w.Host.Output(ctx, "list", "chain", "inet", "fw4", chain)
		if listErr == nil && strings.Contains(string(out), "jump accept_from_"+zone) {
			// The zone accepts every input: the rule would log accepted
			// connections. Leave it out.
			removed, err := w.Host.RemoveFile(Fw4SnippetPath(zone))
			if err != nil {
				return err
			}
			reload = reload || removed
			errs = append(errs, fmt.Errorf("fw4 zone %q accepts all input: WAN-REJECT logging is disabled there", zone))
			continue
		}
		changed, err := w.Host.WriteFile(Fw4SnippetPath(zone), []byte(w.Fw4Snippet()))
		if err != nil {
			return err
		}
		// No chain yet (fw4 not started, or a zone of another name): a
		// reload installs it or reports the problem.
		present := listErr == nil && strings.Contains(string(out), w.tag())
		reload = reload || changed || !present
		if listErr != nil {
			missing = append(missing, zone)
		}
	}
	if reload {
		if err := w.fw4Reload(ctx); err != nil {
			return err
		}
		for _, zone := range missing {
			if _, err := w.Host.Output(ctx, "list", "chain", "inet", "fw4", "input_"+zone); err != nil {
				errs = append(errs, fmt.Errorf("fw4 has no chain input_%s: openpicket.fw4_zones names a zone that does not exist", zone))
			}
		}
	}
	return errors.Join(errs...)
}

// removeSnippets removes the rule from every zone not in keep (and the
// legacy dstnat rule); it reports whether anything was removed.
func (w *WANReject) removeSnippets(keep []string) (bool, error) {
	paths, err := filepath.Glob(w.Host.FS.Path(fw4ChainPost + "/input_*/" + fw4SnippetName))
	if err != nil {
		return false, err
	}
	removed, err := w.Host.RemoveFile(legacyFw4Snippet)
	if err != nil {
		return false, err
	}
	for _, p := range paths {
		zone := strings.TrimPrefix(filepath.Base(filepath.Dir(p)), "input_")
		if slices.Contains(keep, zone) {
			continue
		}
		r, err := w.Host.RemoveFile(Fw4SnippetPath(zone))
		if err != nil {
			return false, err
		}
		removed = removed || r
	}
	return removed, nil
}

func (w *WANReject) fw4Reload(ctx context.Context) error {
	if _, err := w.Host.Exec.Run(ctx, "fw4", []string{"reload"}, nil); err != nil {
		if strings.Contains(err.Error(), "Read-only file system") {
			// fw4 writes /var/run/fw4.lock, which is /tmp/run under a read-only /host.
			return fmt.Errorf("fw4 reload: %w (mount the host /tmp read-write at /host/tmp)", err)
		}
		return fmt.Errorf("fw4 reload: %w", err)
	}
	return nil
}

// Remove uninstalls the rule.
func (w *WANReject) Remove(ctx context.Context) error {
	if w.Mode == "fw4" {
		removed, err := w.removeSnippets(nil)
		if err != nil || !removed {
			return err
		}
		return w.fw4Reload(ctx)
	}
	return w.Host.Apply(ctx, deleteTable("inet", NflogTable))
}
