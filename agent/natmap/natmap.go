// Package natmap keeps the node's recent NAT translations from conntrack
// events, so a Suricata record seen on one side of the NAT can name the
// other side: the inside host behind an outbound alert captured on the WAN
// (after SNAT its source is the node's public address), the public port
// of an inbound alert captured after DNAT.
//
// Flows are kept from their NEW event until retention after their DESTROY
// event: Suricata records are read after the fact, and short flows (DNS)
// are gone from conntrack by then.
package natmap

import (
	"net/netip"
	"sync"
	"time"
)

// Proto numbers handled: flows identified by ports.
const (
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
	ProtoSCTP uint8 = 132
)

// Conntrack status bits (include/uapi/linux/netfilter/nf_conntrack_common.h).
const (
	statusSrcNAT = 1 << 4
	statusDstNAT = 1 << 5
)

// Endpoint is an address and port.
type Endpoint = netip.AddrPort

// Flow is a NAT-translated connection.
type Flow struct {
	ID    uint32
	Proto uint8
	// Orig is the connection as its initiator sent it, Reply as the
	// responder answers it.
	OrigSrc, OrigDst   Endpoint
	ReplySrc, ReplyDst Endpoint
	SNAT, DNAT         bool
}

// Mapping is what a lookup tells about the other side of the NAT.
type Mapping struct {
	// Type is "snat" (an inside host reaching out) or "dnat" (a port
	// forward to an inside host).
	Type string
	// Inside is the inside host and its port.
	Inside Endpoint
	// Public is the node's address and port facing the remote party.
	Public Endpoint
}

// Mapping of the flow.
func (f *Flow) Mapping() Mapping {
	if f.DNAT {
		return Mapping{Type: "dnat", Inside: f.ReplySrc, Public: f.OrigDst}
	}
	return Mapping{Type: "snat", Inside: f.OrigSrc, Public: f.ReplyDst}
}

// key identifies a flow by its client -> server view.
type key struct {
	proto          uint8
	client, server Endpoint
}

type entry struct {
	flow  Flow
	ended time.Time // zero while alive
}

// Table holds the flows. It is safe for concurrent use.
type Table struct {
	retention time.Duration
	max       int
	now       func() time.Time

	mu    sync.Mutex
	flows map[uint32]*entry
	// Both views of each flow: before NAT (orig) and after (reply,
	// turned client -> server).
	index map[key]uint32
	// ended flows, oldest first (pruned by retention and size).
	ended   []uint32
	dropped uint64
}

// NewTable creates a table keeping ended flows for retention and at most
// max flows.
func NewTable(retention time.Duration, max int) *Table {
	return &Table{retention: retention, max: max, now: time.Now, flows: map[uint32]*entry{}, index: map[key]uint32{}}
}

func (f *Flow) keys() [2]key {
	return [2]key{
		{f.Proto, f.OrigSrc, f.OrigDst},
		{f.Proto, f.ReplyDst, f.ReplySrc},
	}
}

// Add records a new (or updated) flow.
func (t *Table) Add(f Flow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked()
	if old, ok := t.flows[f.ID]; ok {
		t.unindexLocked(f.ID, old)
	} else if len(t.flows) >= t.max {
		t.dropped++
		return
	}
	t.flows[f.ID] = &entry{flow: f}
	for _, k := range f.keys() {
		t.index[k] = f.ID
	}
}

// End marks a flow destroyed; it stays for the retention.
func (t *Table) End(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endLocked(id, t.now())
}

func (t *Table) endLocked(id uint32, at time.Time) {
	e, ok := t.flows[id]
	if !ok || !e.ended.IsZero() {
		return
	}
	e.ended = at
	t.ended = append(t.ended, id)
}

// Sync reconciles with a full listing of the live flows (after lost
// events): flows not listed are ended now.
func (t *Table) Sync(live []Flow) {
	seen := make(map[uint32]bool, len(live))
	for _, f := range live {
		seen[f.ID] = true
		t.Add(f)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for id, e := range t.flows {
		if e.ended.IsZero() && !seen[id] {
			t.endLocked(id, now)
		}
	}
}

func (t *Table) unindexLocked(id uint32, e *entry) {
	for _, k := range e.flow.keys() {
		if t.index[k] == id {
			delete(t.index, k)
		}
	}
}

// pruneLocked forgets ended flows past the retention, and the oldest
// ended ones beyond the size limit.
func (t *Table) pruneLocked() {
	now := t.now()
	n := 0
	for n < len(t.ended) {
		id := t.ended[n]
		e, ok := t.flows[id]
		if ok && e.ended.IsZero() {
			// Re-added after it ended (an id reused): not ours to drop.
			n++
			continue
		}
		if ok && now.Sub(e.ended) < t.retention && len(t.flows) < t.max {
			break
		}
		if ok {
			t.unindexLocked(id, e)
			delete(t.flows, id)
		}
		n++
	}
	t.ended = t.ended[n:]
}

// Lookup finds the flow seen as client -> server, on either side of the
// NAT.
func (t *Table) Lookup(proto uint8, client, server Endpoint) (Mapping, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.index[key{proto, client, server}]
	if !ok {
		return Mapping{}, false
	}
	return t.flows[id].flow.Mapping(), true
}

// Stats are the table's counters.
type Stats struct {
	Flows   int
	Dropped uint64
}

// Stats returns the counters.
func (t *Table) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{Flows: len(t.flows), Dropped: t.dropped}
}
