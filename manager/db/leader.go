package db

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotLeader is returned by Fenced when the epoch is no longer current.
var ErrNotLeader = errors.New("db: leadership lost")

// Leadership is held while the context passed to the task is alive.
type Leadership struct {
	Task  string
	Epoch int64
	pool  *pgxpool.Pool
}

// Fenced runs fn in a transaction that commits only while this leadership's
// epoch is still the current one, so a deposed leader cannot write.
func (l *Leadership) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		var epoch int64
		if err := tx.QueryRow(ctx, `SELECT epoch FROM openpicket.leader_epochs WHERE task = $1 FOR SHARE`, l.Task).Scan(&epoch); err != nil {
			return err
		}
		if epoch != l.Epoch {
			return ErrNotLeader
		}
		return fn(tx)
	})
}

func lockKey(task string) int64 {
	h := fnv.New64a()
	h.Write([]byte("openpicket-leader:" + task))
	return int64(h.Sum64())
}

// RunLeader competes for task and runs fn while this replica leads. The
// lock is a session advisory lock on a dedicated connection: it is released
// when the connection drops, so there is no lease to renew. fn's context is
// cancelled when leadership is lost (connection check every few seconds).
func RunLeader(ctx context.Context, pool *pgxpool.Pool, task, holder string, log *slog.Logger, fn func(ctx context.Context, l *Leadership)) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "leader", "task", task)
	for ctx.Err() == nil {
		err := lead(ctx, pool, task, holder, log, fn)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("leader election", "err", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func lead(ctx context.Context, pool *pgxpool.Pool, task, holder string, log *slog.Logger, fn func(ctx context.Context, l *Leadership)) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	pc := conn.Hijack()
	defer pc.Close(context.Background())
	var got bool
	if err := pc.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey(task)).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil
	}
	var epoch int64
	if err := pc.QueryRow(ctx, `INSERT INTO openpicket.leader_epochs (task, epoch, holder, acquired_at) VALUES ($1, 1, $2, now())
		ON CONFLICT (task) DO UPDATE SET epoch = openpicket.leader_epochs.epoch + 1, holder = excluded.holder, acquired_at = now()
		RETURNING epoch`, task, holder).Scan(&epoch); err != nil {
		return err
	}
	log.Info("acquired leadership", "epoch", epoch)
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(lctx, &Leadership{Task: task, Epoch: epoch, pool: pool})
	}()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		case <-done:
			return nil
		case <-t.C:
			pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			err := pc.Ping(pctx)
			pcancel()
			if err != nil {
				log.Warn("lost leadership: lock connection failed", "err", err)
				cancel()
				<-done
				return err
			}
		}
	}
}
