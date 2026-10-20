package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Watermarks remember, per node, agent boot and sink, the last batch the
// sink received. They live in memory and are flushed to PostgreSQL every
// FlushInterval, so another replica taking over a node's session skips
// batches already delivered — except those of the last flush interval
// before a replica crash (the accepted duplicate window, §4.2).
type Watermarks struct {
	db  *pgxpool.Pool
	log *slog.Logger
	// FlushInterval defaults to 1s.
	FlushInterval time.Duration
	// Retention drops rows not updated for this long (default 7 days).
	Retention time.Duration

	mu     sync.Mutex
	mem    map[wmKey]uint64
	dirty  map[wmKey]uint64
	loaded map[wmBoot]bool
}

type wmKey struct{ node, boot, sink string }
type wmBoot struct{ node, boot string }

// NewWatermarks creates the store; call Run.
func NewWatermarks(db *pgxpool.Pool, log *slog.Logger) *Watermarks {
	if log == nil {
		log = slog.Default()
	}
	return &Watermarks{db: db, log: log.With("component", "watermarks"), FlushInterval: time.Second, Retention: 7 * 24 * time.Hour,
		mem: map[wmKey]uint64{}, dirty: map[wmKey]uint64{}, loaded: map[wmBoot]bool{}}
}

// Get returns the last delivered seq (0 if none). The first call for a node
// and boot loads the persisted values; if that fails it returns 0 (deliver
// again rather than lose data).
func (w *Watermarks) Get(ctx context.Context, node, boot, sink string) uint64 {
	nb := wmBoot{node, boot}
	w.mu.Lock()
	ok := w.loaded[nb]
	w.mu.Unlock()
	if !ok {
		w.load(ctx, nb)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mem[wmKey{node, boot, sink}]
}

func (w *Watermarks) load(ctx context.Context, nb wmBoot) {
	if w.db == nil {
		w.mu.Lock()
		w.loaded[nb] = true
		w.mu.Unlock()
		return
	}
	rows, err := w.db.Query(ctx, `SELECT sink, seq FROM openpicket.sink_watermarks WHERE node_id = $1 AND boot_id = $2`, nb.node, nb.boot)
	if err != nil {
		w.log.Warn("load watermarks", "node", nb.node, "err", err)
		return
	}
	got := map[string]uint64{}
	for rows.Next() {
		var (
			sink string
			seq  int64
		)
		if err := rows.Scan(&sink, &seq); err == nil {
			got[sink] = uint64(seq)
		}
	}
	rows.Close()
	if rows.Err() != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for sink, seq := range got {
		k := wmKey{nb.node, nb.boot, sink}
		w.mem[k] = max(w.mem[k], seq)
	}
	w.loaded[nb] = true
}

// Set records a delivery.
func (w *Watermarks) Set(node, boot, sink string, seq uint64) {
	k := wmKey{node, boot, sink}
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq > w.mem[k] {
		w.mem[k] = seq
		w.dirty[k] = seq
	}
}

// Forget drops a node's in-memory watermarks of other boots (call when a
// new agent boot connects).
func (w *Watermarks) Forget(node, keepBoot string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.mem {
		if k.node == node && k.boot != keepBoot {
			delete(w.mem, k)
		}
	}
	for nb := range w.loaded {
		if nb.node == node && nb.boot != keepBoot {
			delete(w.loaded, nb)
		}
	}
}

// Run flushes periodically until ctx is cancelled, then flushes once more.
func (w *Watermarks) Run(ctx context.Context) {
	t := time.NewTicker(w.FlushInterval)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			w.Flush(fctx)
			cancel()
			return
		case <-t.C:
			w.Flush(ctx)
		case <-prune.C:
			if _, err := w.db.Exec(ctx, `DELETE FROM openpicket.sink_watermarks WHERE updated_at < now() - $1::interval`, w.Retention.String()); err != nil {
				w.log.Warn("prune watermarks", "err", err)
			}
		}
	}
}

// Flush writes pending watermarks in one statement.
func (w *Watermarks) Flush(ctx context.Context) {
	if w.db == nil {
		return
	}
	w.mu.Lock()
	if len(w.dirty) == 0 {
		w.mu.Unlock()
		return
	}
	dirty := w.dirty
	w.dirty = map[wmKey]uint64{}
	w.mu.Unlock()
	var nodes, boots, sinks []string
	var seqs []int64
	for k, v := range dirty {
		nodes, boots, sinks, seqs = append(nodes, k.node), append(boots, k.boot), append(sinks, k.sink), append(seqs, int64(v))
	}
	_, err := w.db.Exec(ctx, `INSERT INTO openpicket.sink_watermarks (node_id, boot_id, sink, seq, updated_at)
		SELECT * , now() FROM unnest($1::text[], $2::text[], $3::text[], $4::bigint[])
		ON CONFLICT (node_id, boot_id, sink) DO UPDATE SET seq = GREATEST(openpicket.sink_watermarks.seq, excluded.seq), updated_at = now()`,
		nodes, boots, sinks, seqs)
	if err != nil {
		w.log.Warn("flush watermarks", "err", err)
		// Keep them for the next flush.
		w.mu.Lock()
		for k, v := range dirty {
			if v > w.dirty[k] {
				w.dirty[k] = v
			}
		}
		w.mu.Unlock()
	}
}
