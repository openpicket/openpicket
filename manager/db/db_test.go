package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
)

// One replica leads at a time; a deposed leader cannot write.
func TestLeaderExclusiveAndFenced(t *testing.T) {
	pool := pgtest.Pool(t)
	if err := schema.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	var leaders atomic.Int32
	var maxLeaders atomic.Int32
	var mu sync.Mutex
	var first *Leadership
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i, name := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RunLeader(ctx, pool, "relay", name, nil, func(lctx context.Context, l *Leadership) {
				n := leaders.Add(1)
				if n > maxLeaders.Load() {
					maxLeaders.Store(n)
				}
				mu.Lock()
				if first == nil {
					first = l
				}
				mu.Unlock()
				if i == 0 || l.Epoch == 1 {
					// The first leader steps down after a moment.
					select {
					case <-lctx.Done():
					case <-time.After(300 * time.Millisecond):
					}
				} else {
					<-lctx.Done()
				}
				leaders.Add(-1)
			})
		}()
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		var epoch int64
		if err := pool.QueryRow(ctx, `SELECT epoch FROM openpicket.leader_epochs WHERE task = 'relay'`).Scan(&epoch); err == nil && epoch >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leadership did not move")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if maxLeaders.Load() != 1 {
		t.Fatalf("%d leaders at once", maxLeaders.Load())
	}
	mu.Lock()
	old := first
	mu.Unlock()
	err := old.Fenced(context.Background(), func(pgx.Tx) error { return nil })
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("deposed leader write: %v", err)
	}
	cancel()
	wg.Wait()
}

func TestListenerDispatchesAndResyncs(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := NewListener(pool, nil)
	got := make(chan string, 4)
	resynced := make(chan struct{}, 4)
	l.Handle(ChannelNodes, func(p string) { got <- p })
	l.OnResync(func() { resynced <- struct{}{} })
	go l.Run(ctx)
	select {
	case <-resynced:
	case <-time.After(10 * time.Second):
		t.Fatal("no resync on connect")
	}
	if _, err := pool.Exec(ctx, `SELECT pg_notify($1, 'node-7')`, ChannelNodes); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if p != "node-7" {
			t.Fatalf("payload %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("notification not delivered")
	}
}

// One connection holds every lock of a replica; the tasks of a stopped
// replica move to another, and a task that returns lets go of its lock.
func TestElectorSharesOneConnection(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	tasks := []string{"relay", "notify", "alerts", "misp"}
	var mu sync.Mutex
	leading := map[string]string{} // task -> replica
	double := ""
	// stopOnce: the task returns once, in its first epoch.
	start := func(name string, stopOnce string) (context.CancelFunc, chan struct{}) {
		e := NewElector(pool, name, nil)
		for _, task := range tasks {
			e.Add(task, func(lctx context.Context, l *Leadership) {
				mu.Lock()
				if other, ok := leading[task]; ok {
					double = task + " led by " + other + " and " + name
				}
				leading[task] = name
				mu.Unlock()
				var stop <-chan time.Time
				if task == stopOnce && l.Epoch == 1 {
					stop = time.After(200 * time.Millisecond)
				}
				select {
				case <-lctx.Done():
				case <-stop:
				}
				mu.Lock()
				delete(leading, task)
				mu.Unlock()
			})
		}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { e.Run(ectx); close(done) }()
		return cancel, done
	}
	waitUntil := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// pg_locks spans the cluster: other test packages take advisory locks
	// in their own databases at the same time (migrations, seeding).
	lockHolders := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(DISTINCT pid) FROM pg_locks WHERE locktype = 'advisory' AND granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ledBy := func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, r := range leading {
			if r == name {
				n++
			}
		}
		return n
	}

	// a starts alone and leads everything on one connection; "notify"
	// returns after a moment and is taken again.
	stopA, doneA := start("a", "notify")
	var epoch int64
	waitUntil("notify taken again", func() bool {
		_ = pool.QueryRow(ctx, `SELECT epoch FROM openpicket.leader_epochs WHERE task = 'notify'`).Scan(&epoch)
		return epoch >= 2
	})
	waitUntil("a leads every task", func() bool { return ledBy("a") == len(tasks) })
	if n := lockHolders(); n != 1 {
		t.Fatalf("%d sessions hold the locks", n)
	}

	stopB, doneB := start("b", "")
	defer func() { stopB(); <-doneB }()
	stopA()
	<-doneA
	waitUntil("b takes over", func() bool { return ledBy("b") == len(tasks) })
	if n := lockHolders(); n != 1 {
		t.Fatalf("%d sessions hold the locks after the takeover", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if double != "" {
		t.Fatal(double)
	}
}
