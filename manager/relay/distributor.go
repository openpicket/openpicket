package relay

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// Distributor streams the edge view to the nodes connected to this replica:
// a snapshot when a node has nothing usable, deltas afterwards. TTLs are
// computed from the stored until at send time, so resending never extends
// a block (§4.3 TTL contract).
type Distributor struct {
	db  *pgxpool.Pool
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	changed chan struct{}
}

// NewDistributor creates a distributor. Call Notified on every
// openpicket_decisions notification.
func NewDistributor(pool *pgxpool.Pool, log *slog.Logger) *Distributor {
	if log == nil {
		log = slog.Default()
	}
	return &Distributor{db: pool, log: log.With("component", "distributor"), now: time.Now, changed: make(chan struct{})}
}

// Notified wakes every stream (the edge view changed).
func (d *Distributor) Notified(string) {
	d.mu.Lock()
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}

func (d *Distributor) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.changed
}

func toDirection(s string) dataplanev1.Direction {
	if s == DirBoth {
		return dataplanev1.Direction_DIRECTION_BOTH
	}
	return dataplanev1.Direction_DIRECTION_INBOUND
}

func toScope(s string) dataplanev1.Scope {
	if s == "range" {
		return dataplanev1.Scope_SCOPE_RANGE
	}
	return dataplanev1.Scope_SCOPE_IP
}

// view reads, in one consistent snapshot, the current version and either
// the whole set (snapshot) or the changes after have (delta).
func (d *Distributor) view(ctx context.Context, have uint64) (*dataplanev1.DecisionsDown, uint64, error) {
	var out *dataplanev1.DecisionsDown
	var version uint64
	err := pgx.BeginTxFunc(ctx, d.db, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var cur, horizon int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT max(version) FROM openpicket.edge_decisions), 0), (SELECT horizon FROM openpicket.edge_meta WHERE id = 1)`).Scan(&cur, &horizon); err != nil {
			return err
		}
		version = uint64(cur)
		now := d.now()
		if have != 0 && have >= uint64(horizon) && have <= uint64(cur) {
			if have == uint64(cur) {
				return nil
			}
			rows, err := tx.Query(ctx, `SELECT value, scope, direction, until, origin, scenario, deleted FROM openpicket.edge_decisions WHERE version > $1`, int64(have))
			if err != nil {
				return err
			}
			defer rows.Close()
			delta := &dataplanev1.DecisionDelta{FromVersion: have, ToVersion: uint64(cur)}
			for rows.Next() {
				var (
					value, scope, dir, origin, scenario string
					until                               time.Time
					deleted                             bool
				)
				if err := rows.Scan(&value, &scope, &dir, &until, &origin, &scenario, &deleted); err != nil {
					return err
				}
				ttl := until.Sub(now)
				if deleted || ttl <= 0 {
					delta.Deletes = append(delta.Deletes, value)
					continue
				}
				delta.Upserts = append(delta.Upserts, &dataplanev1.Decision{Value: value, Scope: toScope(scope), Direction: toDirection(dir),
					TtlMs: ttl.Milliseconds(), Origin: origin, Scenario: scenario})
			}
			out = &dataplanev1.DecisionsDown{Body: &dataplanev1.DecisionsDown_Delta{Delta: delta}}
			return rows.Err()
		}
		rows, err := tx.Query(ctx, `SELECT value, scope, direction, until, origin, scenario FROM openpicket.edge_decisions WHERE NOT deleted AND until > $1`, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		snap := &dataplanev1.DecisionSnapshot{Version: uint64(cur)}
		for rows.Next() {
			var (
				value, scope, dir, origin, scenario string
				until                               time.Time
			)
			if err := rows.Scan(&value, &scope, &dir, &until, &origin, &scenario); err != nil {
				return err
			}
			snap.Decisions = append(snap.Decisions, &dataplanev1.Decision{Value: value, Scope: toScope(scope), Direction: toDirection(dir),
				TtlMs: until.Sub(now).Milliseconds(), Origin: origin, Scenario: scenario})
		}
		out = &dataplanev1.DecisionsDown{Body: &dataplanev1.DecisionsDown_Snapshot{Snapshot: snap}}
		return rows.Err()
	})
	return out, version, err
}

// Serve runs the decisions stream of one node until it ends.
func (d *Distributor) Serve(ctx context.Context, nodeID string, ms *wire.MsgStream) error {
	up := &dataplanev1.DecisionsUp{}
	if err := ms.Recv(up); err != nil {
		return err
	}
	sub := up.GetSubscribe()
	if sub == nil {
		return errors.New("distributor: first message must be a subscribe")
	}
	have := sub.HaveVersion
	acks := make(chan *dataplanev1.DecisionAck, 1)
	errc := make(chan error, 1)
	go func() {
		for {
			m := &dataplanev1.DecisionsUp{}
			if err := ms.Recv(m); err != nil {
				errc <- err
				return
			}
			if a := m.GetAck(); a != nil {
				select {
				case acks <- a:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	periodic := time.NewTicker(30 * time.Second)
	defer periodic.Stop()
	for {
		changed := d.wait()
		msg, version, err := d.view(ctx, have)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Database unavailable: the node keeps what it has.
			d.log.Warn("read edge decisions", "node", nodeID, "err", err)
		} else if msg != nil {
			if err := ms.Send(msg); err != nil {
				return err
			}
			select {
			case a := <-acks:
				d.record(ctx, nodeID, a)
				if a.Error != "" {
					d.log.Warn("node could not apply decisions", "node", nodeID, "version", version, "err", a.Error)
					// Version mismatch or a partial failure: resync.
					have = 0
				} else {
					have = a.Version
				}
				if a.Error == "" && have != version {
					have = 0
				}
				continue
			case err := <-errc:
				return err
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Minute):
				return errors.New("distributor: no acknowledgement")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case <-changed:
		case <-periodic.C:
		}
	}
}

func (d *Distributor) record(ctx context.Context, nodeID string, a *dataplanev1.DecisionAck) {
	if _, err := d.db.Exec(ctx, `INSERT INTO openpicket.node_decision_state (node_id, version, set_size, error, acked_at)
		VALUES ($1,$2,$3,$4,now()) ON CONFLICT (node_id) DO UPDATE SET version=excluded.version, set_size=excluded.set_size,
		error=excluded.error, acked_at=excluded.acked_at`, nodeID, int64(a.Version), int32(a.SetSize), a.Error); err != nil {
		d.log.Debug("record decision ack", "node", nodeID, "err", err)
	}
}
