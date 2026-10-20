package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"time"
)

// allowlist holds the networks the node never blocks: the configured ones
// and, for the "controller" entry, the current addresses of the
// suricontroller and manager hosts (so a decision cannot cut the node off
// its management).
type allowlist struct {
	static  []netip.Prefix
	hosts   []string
	log     *slog.Logger
	current atomic.Pointer[[]netip.Prefix]
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
}

func newAllowlist(entries []string, urls []string, log *slog.Logger) *allowlist {
	a := &allowlist{log: log, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
	controller := false
	for _, e := range entries {
		if e == "controller" {
			controller = true
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			a.static = append(a.static, p.Masked())
		} else if ad, err := netip.ParseAddr(e); err == nil {
			ad = ad.Unmap()
			a.static = append(a.static, netip.PrefixFrom(ad, ad.BitLen()))
		}
	}
	if controller {
		for _, u := range urls {
			if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
				a.hosts = append(a.hosts, pu.Hostname())
			}
		}
	}
	s := slices.Clone(a.static)
	a.current.Store(&s)
	return a
}

// Prefixes returns the current allowlist.
func (a *allowlist) Prefixes() []netip.Prefix { return *a.current.Load() }

func (a *allowlist) refresh(ctx context.Context) {
	out := slices.Clone(a.static)
	for _, h := range a.hosts {
		if ad, err := netip.ParseAddr(h); err == nil {
			ad = ad.Unmap()
			out = append(out, netip.PrefixFrom(ad, ad.BitLen()))
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, err := a.lookup(lctx, h)
		cancel()
		if err != nil {
			a.log.Warn("resolve controller host for the allowlist; keeping previous addresses", "host", h, "err", err)
			// Keep what we had for this host rather than dropping it.
			for _, p := range a.Prefixes() {
				if !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
			continue
		}
		for _, ad := range addrs {
			ad = ad.Unmap()
			out = append(out, netip.PrefixFrom(ad, ad.BitLen()))
		}
	}
	slices.SortFunc(out, func(x, y netip.Prefix) int { return x.Addr().Compare(y.Addr()) })
	out = slices.Compact(out)
	a.current.Store(&out)
}

func (a *allowlist) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
		a.refresh(ctx)
	}
}
