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
