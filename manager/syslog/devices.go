// Package syslog receives syslog from devices without an agent (switches,
// firewalls, NAS) on the gateways (docs/ARCHITECTURE.md §4.10): UDP, TCP
// (newline or octet-counting framing, RFC 6587) and TLS (RFC 5425). The
// device is taken from the sender's address; its lines go through the log
// pipeline as generic logs (CrowdSec, Loki) at most once.
package syslog

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/pkg/record"
)

// KeyUnregistered is the setting deciding what happens to messages of
// senders no device matches: ModeDrop or ModeAccept.
const KeyUnregistered = "syslog.unregistered"

// Modes of KeyUnregistered.
const (
	// ModeDrop drops them (they are counted per sender).
	ModeDrop = "drop"
	// ModeAccept takes them in as a temporary device named after the
	// sender's address (TempID).
	ModeAccept = "accept"
)

// ValidMode reports whether m is a mode.
func ValidMode(m string) bool { return m == ModeDrop || m == ModeAccept }

// ProgramDefault is the Programs key naming lines without a syslog header.
const ProgramDefault = "*"

// Device is a syslog sender.
type Device struct {
	ID      string
	Sources []netip.Prefix
	Labels  map[string]string
	// Programs renames syslog tags; ProgramDefault names lines without a
	// header.
	Programs map[string]string
	Enabled  bool
	// Registered is false for a temporary device (ModeAccept).
	Registered bool

	node *registry.Node
}

// Program returns the program of a line with syslog tag tag ("" when the
// line has no header).
func (d *Device) Program(tag string) string {
	if tag == "" {
		tag = ProgramDefault
	}
	if p, ok := d.Programs[tag]; ok {
		return p
	}
	if tag == ProgramDefault {
		return "unknown"
	}
	if p := record.NormalizeProgram(tag); p != "" {
		return p
	}
	return "unknown"
}

// Node is the device as the pipeline's sinks see a node.
func (d *Device) Node() *registry.Node { return d.node }

// TempID is the device id of an unregistered sender: its address (an
// IPv6 address with dashes for colons, prefixed with "ip6-").
func TempID(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	return "ip6-" + strings.ReplaceAll(addr.String(), ":", "-")
}

// Devices holds the devices, matched by sender address, and the mode for
// unregistered senders.
type Devices struct {
	db       *pgxpool.Pool
	settings *settings.Store
	def      string
	log      *slog.Logger

	table atomic.Pointer[table]
	mode  atomic.Value // string
}

type entry struct {
	prefix netip.Prefix
	dev    *Device
}

// table is sorted by prefix length, longest first.
type table []entry

// NewDevices creates the device table; defaultMode applies until the
// setting is stored (ModeDrop when empty).
func NewDevices(db *pgxpool.Pool, st *settings.Store, defaultMode string, log *slog.Logger) *Devices {
	if !ValidMode(defaultMode) {
		defaultMode = ModeDrop
	}
	d := &Devices{db: db, settings: st, def: defaultMode, log: log.With("component", "syslog")}
	d.table.Store(&table{})
	d.mode.Store(defaultMode)
	return d
}

// Load reads the devices and the mode.
func (d *Devices) Load(ctx context.Context) error {
	rows, err := d.db.Query(ctx, `SELECT id, sources, labels, programs, enabled FROM openpicket.syslog_devices`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var t table
	for rows.Next() {
		dev := &Device{Registered: true}
		var labels, programs []byte
		if err := rows.Scan(&dev.ID, &dev.Sources, &labels, &programs, &dev.Enabled); err != nil {
			return err
		}
		_ = json.Unmarshal(labels, &dev.Labels)
		_ = json.Unmarshal(programs, &dev.Programs)
		dev.node = &registry.Node{ID: dev.ID, Enabled: dev.Enabled, Labels: dev.Labels}
		for _, p := range dev.Sources {
			t = append(t, entry{prefix: p.Masked(), dev: dev})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sort.SliceStable(t, func(i, j int) bool { return t[i].prefix.Bits() > t[j].prefix.Bits() })
	d.table.Store(&t)
	d.LoadMode(ctx)
	return nil
}

// LoadMode reads the mode setting.
func (d *Devices) LoadMode(ctx context.Context) {
	mode := d.def
	var stored string
	if ok, err := d.settings.Get(ctx, KeyUnregistered, &stored); err != nil {
		d.log.Warn("read the unregistered sender setting", "err", err)
		return
	} else if ok && ValidMode(stored) {
		mode = stored
	}
	d.mode.Store(mode)
}

// Mode returns the mode for unregistered senders.
func (d *Devices) Mode() string { return d.mode.Load().(string) }

// Default returns the mode applying while none is stored.
func (d *Devices) Default() string { return d.def }

// Match returns the device of a sender: a registered one, a temporary one
// (ModeAccept) or nil (ModeDrop).
func (d *Devices) Match(addr netip.Addr) *Device {
	addr = addr.Unmap().WithZone("")
	for _, e := range *d.table.Load() {
		if e.prefix.Contains(addr) {
			return e.dev
		}
	}
	if d.Mode() != ModeAccept {
		return nil
	}
	id := TempID(addr)
	return &Device{ID: id, Enabled: true, Sources: []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())},
		node: &registry.Node{ID: id, Enabled: true}}
}
