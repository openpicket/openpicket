package natmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	ct "github.com/florianl/go-conntrack"
)

// resyncInterval: the table is reconciled with a full listing this often
// (DESTROY events can be lost).
const resyncInterval = 10 * time.Minute

// readBuffer of the event socket: bursts of new connections overflow the
// default and lose events.
const readBuffer = 4 << 20

// Tracker feeds a Table from conntrack events.
type Tracker struct {
	Table  *Table
	Logger *slog.Logger

	mu      sync.Mutex
	lastErr string
	resyncs uint64
	ready   bool
}

// ErrUnavailable: the kernel offers no conntrack netlink interface.
var ErrUnavailable = errors.New("conntrack events unavailable (nf_conntrack_netlink; on OpenWrt: opkg install kmod-nf-conntrack-netlink)")

// Run follows conntrack until ctx ends, resubscribing after errors.
func (t *Tracker) Run(ctx context.Context) {
	if t.Logger == nil {
		t.Logger = slog.Default()
	}
	backoff := time.Second
	for ctx.Err() == nil {
		err := t.session(ctx)
		if ctx.Err() != nil {
			return
		}
		t.setErr(err)
		t.Logger.Warn("conntrack events stopped; resubscribing", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// session subscribes, loads the current flows and follows events until an
// error. Events received while listing are applied after it, so nothing
// between the listing and the subscription is lost.
func (t *Tracker) session(ctx context.Context) error {
	// AddConntrackInformation tells NEW from DESTROY events.
	nfct, err := ct.Open(&ct.Config{Logger: log.New(io.Discard, "", 0), AddConntrackInformation: true})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer nfct.Close()
	_ = nfct.Con.SetReadBuffer(readBuffer)
	errc := nfct.AttachErrChan()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events := make(chan ct.Con, 4096)
	hook := func(c ct.Con) int {
		select {
		case events <- c:
		case <-sctx.Done():
			return 1
		}
		return 0
	}
	if err := nfct.Register(sctx, ct.Conntrack, ct.NetlinkCtNew|ct.NetlinkCtDestroy, hook); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := t.resync(); err != nil {
		return err
	}
	t.setErr(nil)
	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return fmt.Errorf("conntrack events: %w (events lost; the table is listed again)", err)
		case <-tick.C:
			if err := t.resync(); err != nil {
				return err
			}
		case c := <-events:
			t.apply(c)
		}
	}
}

// resync lists the current flows (a second socket: the event socket is
// busy receiving).
func (t *Tracker) resync() error {
	nfct, err := ct.Open(&ct.Config{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer nfct.Close()
	var live []Flow
	for _, fam := range []ct.Family{ct.IPv4, ct.IPv6} {
		cons, err := nfct.Dump(ct.Conntrack, fam)
		if err != nil {
			return fmt.Errorf("list conntrack: %w", err)
		}
		for _, c := range cons {
			if f, ok := flowOf(c); ok {
				live = append(live, f)
			}
		}
	}
	t.Table.Sync(live)
	t.mu.Lock()
	t.resyncs++
	t.ready = true
	t.mu.Unlock()
	return nil
}

func (t *Tracker) apply(c ct.Con) {
	if c.ID == nil {
		return
	}
	if c.Info != nil && c.Info.NetlinkGroup == ct.NetlinkCtDestroy {
		t.Table.End(*c.ID)
		return
	}
	if f, ok := flowOf(c); ok {
		t.Table.Add(f)
	}
}

// flowOf converts a NAT-translated connection with ports.
func flowOf(c ct.Con) (Flow, bool) {
	if c.ID == nil || c.Status == nil || c.Origin == nil || c.Reply == nil || *c.Status&(statusSrcNAT|statusDstNAT) == 0 {
		return Flow{}, false
	}
	o, r := c.Origin, c.Reply
	if o.Proto == nil || o.Proto.Number == nil {
		return Flow{}, false
	}
	switch *o.Proto.Number {
	case ProtoTCP, ProtoUDP, ProtoSCTP:
	default:
		return Flow{}, false
	}
	os, ok1 := endpoint(o.Src, o.Proto.SrcPort)
	od, ok2 := endpoint(o.Dst, o.Proto.DstPort)
	rs, ok3 := endpoint(r.Src, protoPort(r, true))
	rd, ok4 := endpoint(r.Dst, protoPort(r, false))
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Flow{}, false
	}
	return Flow{ID: *c.ID, Proto: *o.Proto.Number, OrigSrc: os, OrigDst: od, ReplySrc: rs, ReplyDst: rd,
		SNAT: *c.Status&statusSrcNAT != 0, DNAT: *c.Status&statusDstNAT != 0}, true
}

func protoPort(t *ct.IPTuple, src bool) *uint16 {
	if t.Proto == nil {
		return nil
	}
	if src {
		return t.Proto.SrcPort
	}
	return t.Proto.DstPort
}

func endpoint(ip *net.IP, port *uint16) (Endpoint, bool) {
	if ip == nil || port == nil {
		return Endpoint{}, false
	}
	a, ok := netip.AddrFromSlice(*ip)
	if !ok {
		return Endpoint{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), *port), true
}

func (t *Tracker) setErr(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil {
		t.lastErr = ""
	} else {
		t.lastErr = err.Error()
	}
}

// State is the tracker's state for status reports.
type State struct {
	// Ready: the current flows were listed at least once.
	Ready   bool
	Resyncs uint64
	LastErr string
}

// State returns the tracker's state.
func (t *Tracker) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return State{Ready: t.ready, Resyncs: t.resyncs, LastErr: t.lastErr}
}
