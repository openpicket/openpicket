package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The WAN is wan_interfaces plus, on OpenWrt, the devices of the fw4 WAN
// zones (fw4_zones). fw4 resolves a zone's networks to their current
// devices, so the list follows interfaces added to a zone, a second
// uplink, or a PPPoE device name.

// zoneDevices is the saved list of fw4 zone devices: at boot, bans and
// policies are restored before fw4 may have loaded its rules.
func (a *Agent) zoneDevicesFile() string {
	return filepath.Join(a.cfg.Suri.StateDir, "openpicket", "wan.json")
}

func (a *Agent) loadZoneDevices() []string {
	raw, err := os.ReadFile(a.zoneDevicesFile())
	if err != nil {
		return nil
	}
	var devs []string
	if json.Unmarshal(raw, &devs) != nil {
		return nil
	}
	return devs
}

func (a *Agent) saveZoneDevices(devs []string) {
	p := a.zoneDevicesFile()
	raw, _ := json.Marshal(devs)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err == nil {
		err = os.WriteFile(p+".tmp", raw, 0o600)
		if err == nil {
			err = os.Rename(p+".tmp", p)
		}
		if err == nil {
			return
		}
	}
	a.log.Warn("save fw4 zone devices", "path", p)
}

// refreshWAN reads the fw4 zone devices again; it reports a change of the
// WAN list.
//
// A device that disappears from the zone while it does not exist on the
// host (a PPPoE link that is down) stays: when the link comes back, it is
// a WAN at once, not at the next refresh. A device that exists and left
// the zone is removed.
func (a *Agent) refreshWAN(ctx context.Context) bool {
	if !a.fw4 {
		return false
	}
	zones, err := a.host.Fw4ZoneDevices(ctx)
	if err != nil {
		// fw4 reloading, or not started yet: keep the current list.
		a.log.Debug("read fw4 zone devices", "err", err)
		return false
	}
	var devs, empty []string
	for _, z := range a.cfg.OpenPicket.Fw4Zones {
		if len(zones[z]) > 0 {
			devs = append(devs, zones[z]...)
			continue
		}
		empty = append(empty, z)
		if !slices.Contains(a.emptyZones, z) {
			a.log.Warn("fw4 zone has no devices: unknown zone, a zone matched by subnet only, or all its networks down", "zone", z)
		}
	}
	a.emptyZones = empty
	for _, d := range a.zoneDevs {
		if !slices.Contains(devs, d) && !strings.HasSuffix(d, "*") && !ifaceExists(d) {
			devs = append(devs, d)
		}
	}
	slices.Sort(devs)
	devs = slices.Compact(devs)
	if !slices.Equal(devs, a.zoneDevs) {
		a.zoneDevs = devs
		a.saveZoneDevices(devs)
	}
	return a.wan.Set(append(slices.Clone(a.cfg.OpenPicket.WANInterfaces), devs...))
}

var ifaceExists = func(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// applyWAN brings the tables in line with a new WAN list.
func (a *Agent) applyWAN(ctx context.Context) {
	a.log.Info("WAN interfaces changed", "wan", a.wan.Get())
	if a.enf != nil {
		if err := a.enf.Ensure(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("update the ban table WAN", "err", err)
		}
	}
	if a.pol != nil {
		if err := a.pol.Ensure(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("update the policy table WAN", "err", err)
		}
	}
	if a.reject != nil && a.reject.Mode == "nftables" {
		if err := a.reject.Ensure(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("update the WAN-REJECT rule", "mode", a.reject.Mode, "err", err)
		}
	}
}
