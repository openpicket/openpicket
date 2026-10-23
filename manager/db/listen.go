// Package db holds the manager's PostgreSQL helpers: notifications shared
// by all replicas and leader election for single-writer tasks.
package db

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Notification channels.
const (
	ChannelNodes     = "openpicket_nodes"
	ChannelSessions  = "openpicket_sessions"
	ChannelSettings  = "openpicket_settings"
	ChannelDecisions = "openpicket_decisions"
	ChannelPolicy    = "openpicket_policy"
	ChannelGeo       = "openpicket_geo"
	ChannelAlerts    = "openpicket_alerts"
	ChannelMISP      = "openpicket_misp"
	ChannelHub       = "openpicket_hub"
)

// Listener keeps a dedicated connection listening on notification channels
// and dispatches payloads. After a reconnect, notifications may have been
// missed: OnResync handlers run so subscribers reload their state.
type Listener struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	mu       sync.Mutex
	handlers map[string][]func(payload string)
	resync   []func()
}

// NewListener creates a listener; call Run.
func NewListener(pool *pgxpool.Pool, log *slog.Logger) *Listener {
	if log == nil {
		log = slog.Default()
	}
	return &Listener{pool: pool, log: log.With("component", "listener"), handlers: map[string][]func(string){}}
}

// Handle registers fn for a channel. Register before Run.
func (l *Listener) Handle(channel string, fn func(payload string)) {
	l.mu.Lock()
	l.handlers[channel] = append(l.handlers[channel], fn)
	l.mu.Unlock()
}

// OnResync registers fn to run after every (re)connect.
func (l *Listener) OnResync(fn func()) {
	l.mu.Lock()
	l.resync = append(l.resync, fn)
	l.mu.Unlock()
}

// Run listens until ctx is cancelled, reconnecting on errors.
func (l *Listener) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := l.listen(ctx)
		if ctx.Err() != nil {
			return
		}
		l.log.Warn("notification listener lost its connection", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (l *Listener) listen(ctx context.Context) error {
	pooled, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// The connection carries LISTEN state; never return it to the pool.
	conn := pooled.Hijack()
	defer conn.Close(context.Background())
	l.mu.Lock()
	channels := make([]string, 0, len(l.handlers))
	for ch := range l.handlers {
		channels = append(channels, ch)
	}
	resync := append([]func(){}, l.resync...)
	l.mu.Unlock()
	for _, ch := range channels {
		if _, err := conn.Exec(ctx, "LISTEN "+ch); err != nil {
			return err
		}
	}
	for _, fn := range resync {
		fn()
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		l.mu.Lock()
		hs := l.handlers[n.Channel]
		l.mu.Unlock()
		for _, fn := range hs {
			fn(n.Payload)
		}
	}
}
