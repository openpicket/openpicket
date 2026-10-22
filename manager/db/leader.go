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

// RunLeader competes for one task; see Elector.
func RunLeader(ctx context.Context, pool *pgxpool.Pool, task, holder string, log *slog.Logger, fn func(ctx context.Context, l *Leadership)) {
	e := NewElector(pool, holder, log)
	e.Add(task, fn)
	e.Run(ctx)
}

// Elector competes for a replica's tasks and runs each one while this
// replica leads it. The locks are session advisory locks on one dedicated
// connection for all tasks: they are released when the connection drops,
// so there is no lease to renew. A task's context is cancelled when
// leadership is lost (connection check every few seconds).
type Elector struct {
	pool   *pgxpool.Pool
	holder string
	log    *slog.Logger
	tasks  []*electorTask
}

type electorTask struct {
	name string
	fn   func(ctx context.Context, l *Leadership)
	log  *slog.Logger
}

// Election timing.
const (
	electRetry = 5 * time.Second
	electPing  = 3 * time.Second
)

// NewElector creates an elector for the replica holder.
func NewElector(pool *pgxpool.Pool, holder string, log *slog.Logger) *Elector {
	if log == nil {
		log = slog.Default()
	}
	return &Elector{pool: pool, holder: holder, log: log.With("component", "leader")}
}

// Add registers a task; call it before Run.
func (e *Elector) Add(task string, fn func(ctx context.Context, l *Leadership)) {
	e.tasks = append(e.tasks, &electorTask{name: task, fn: fn, log: e.log.With("task", task)})
}

// Run competes for the tasks until ctx ends.
func (e *Elector) Run(ctx context.Context) {
	if len(e.tasks) == 0 {
		return
	}
	for ctx.Err() == nil {
		err := e.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			e.log.Warn("leader election", "err", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(electRetry):
		}
	}
}

// running is a task this replica leads.
type running struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// session holds the lock connection until it fails or ctx ends. Only this
// goroutine uses the connection.
func (e *Elector) session(ctx context.Context) error {
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	pc := conn.Hijack()
	defer pc.Close(context.Background())
	led := map[*electorTask]*running{}
	// Tasks stop before the connection (and so the locks) goes.
	defer func() {
		for _, r := range led {
			r.cancel()
		}
		for _, r := range led {
			<-r.done
		}
	}()
	ended := make(chan *electorTask, len(e.tasks))
	next := map[*electorTask]time.Time{}
	lastPing := time.Now()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		now := time.Now()
		for _, task := range e.tasks {
			if led[task] != nil || now.Before(next[task]) {
				continue
			}
			next[task] = now.Add(electRetry)
			r, err := e.try(ctx, pc, task, ended)
			if err != nil {
				return err
			}
			if r != nil {
				led[task] = r
			}
			lastPing = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil
		case task := <-ended:
			// The task returned on its own: let another replica lead it.
			<-led[task].done
			delete(led, task)
			if _, err := pc.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockKey(task.name)); err != nil {
				return err
			}
			next[task] = time.Now().Add(electRetry)
		case <-t.C:
			if len(led) > 0 && time.Since(lastPing) >= electPing {
				pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
				err := pc.Ping(pctx)
				pcancel()
				if err != nil {
					for task := range led {
						task.log.Warn("lost leadership: lock connection failed", "err", err)
					}
					return err
				}
				lastPing = time.Now()
			}
		}
	}
}

// try takes the lock of task and starts it; nil when another replica leads.
func (e *Elector) try(ctx context.Context, pc *pgx.Conn, task *electorTask, ended chan<- *electorTask) (*running, error) {
	var got bool
	if err := pc.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey(task.name)).Scan(&got); err != nil {
		return nil, err
	}
	if !got {
		return nil, nil
	}
	var epoch int64
	if err := pc.QueryRow(ctx, `INSERT INTO openpicket.leader_epochs (task, epoch, holder, acquired_at) VALUES ($1, 1, $2, now())
		ON CONFLICT (task) DO UPDATE SET epoch = openpicket.leader_epochs.epoch + 1, holder = excluded.holder, acquired_at = now()
		RETURNING epoch`, task.name, e.holder).Scan(&epoch); err != nil {
		return nil, err
	}
	task.log.Info("acquired leadership", "epoch", epoch)
	lctx, cancel := context.WithCancel(ctx)
	r := &running{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		defer cancel()
		task.fn(lctx, &Leadership{Task: task.name, Epoch: epoch, pool: e.pool})
		if ctx.Err() == nil && lctx.Err() == nil {
			ended <- task
		}
	}()
	return r, nil
}
