package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// allowlist holds the networks the node never blocks: the configured ones
// and, for the "controller" entry, the current addresses of the
// suricontroller and manager hosts (so a decision cannot cut the node off
// its management).
type allowlist struct {
	static     []netip.Prefix
	hosts      []string
	controller bool
	// learned is the host of the controller URL from the manager (mu).
	mu      sync.Mutex
	learned string
	log     *slog.Logger
	current atomic.Pointer[[]netip.Prefix]
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
}

func newAllowlist(entries []string, urls []string, log *slog.Logger) *allowlist {
	a := &allowlist{log: log, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
	for _, e := range entries {
		if e == "controller" {
			a.controller = true
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			a.static = append(a.static, p.Masked())
		} else if ad, err := netip.ParseAddr(e); err == nil {
			ad = ad.Unmap()
			a.static = append(a.static, netip.PrefixFrom(ad, ad.BitLen()))
		}
	}
	if a.controller {
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

// learn adds the host of the controller URL from the manager to the
// "controller" entry; it reports a change (refresh to apply it).
func (a *allowlist) learn(u string) bool {
	pu, err := url.Parse(u)
	if !a.controller || err != nil || pu.Hostname() == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.learned == pu.Hostname() {
		return false
	}
	a.learned = pu.Hostname()
	return true
}

func (a *allowlist) hostList() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.learned == "" || slices.Contains(a.hosts, a.learned) {
		return a.hosts
	}
	return append(slices.Clone(a.hosts), a.learned)
}

// Prefixes returns the current allowlist.
func (a *allowlist) Prefixes() []netip.Prefix { return *a.current.Load() }

func (a *allowlist) refresh(ctx context.Context) {
	out := slices.Clone(a.static)
	for _, h := range a.hostList() {
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
