package syslog

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxSample bounds the latest message kept per sender.
const maxSample = 512

// Sources counts the messages of each sender for the UI
// (openpicket.syslog_sources), flushed every 30 seconds.
type Sources struct {
	db  *pgxpool.Pool
	log *slog.Logger
	// Max bounds the senders kept between flushes (spoofed UDP senders);
	// messages of more are not counted.
	Max int

	mu       sync.Mutex
	pending  map[netip.Addr]*sourceCount
	overflow uint64
}

type sourceCount struct {
	device            string
	messages, dropped int64
	sample            string
	last              time.Time
}

// NewSources creates the counters.
func NewSources(db *pgxpool.Pool, log *slog.Logger) *Sources {
	return &Sources{db: db, log: log.With("component", "syslog"), Max: 10000, pending: map[netip.Addr]*sourceCount{}}
}

// Seen counts a message of addr taken for device ("" when unregistered),
// or dropped.
func (s *Sources) Seen(addr netip.Addr, device string, dropped bool, line []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.pending[addr]
	if c == nil {
		if len(s.pending) >= s.Max {
			s.overflow++
			return
		}
		c = &sourceCount{}
		s.pending[addr] = c
	}
	c.device, c.last = device, now
	if dropped {
		c.dropped++
	} else {
		c.messages++
	}
	if len(line) > maxSample {
		line = line[:maxSample]
	}
	// The column is text: valid UTF-8 without NUL.
	c.sample = strings.ReplaceAll(strings.ToValidUTF8(string(line), "\uFFFD"), "\x00", "")
}

// Run flushes the counts every 30 seconds and removes senders not seen
// for 30 days, until ctx ends (then it flushes once more).
func (s *Sources) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			s.Flush(ctx)
		case <-prune.C:
			if _, err := s.db.Exec(ctx, `DELETE FROM openpicket.syslog_sources WHERE last_seen < now() - interval '30 days'`); err != nil {
				s.log.Warn("prune syslog senders", "err", err)
			}
		}
	}
}

// Flush writes the pending counts.
func (s *Sources) Flush(ctx context.Context) {
	s.mu.Lock()
	pending, overflow := s.pending, s.overflow
	s.pending, s.overflow = map[netip.Addr]*sourceCount{}, 0
	s.mu.Unlock()
	if overflow > 0 {
		s.log.Warn("too many syslog senders: messages not counted", "messages", overflow)
	}
	if len(pending) == 0 {
		return
	}
	b := &pgx.Batch{}
	for addr, c := range pending {
		var device *string
		if c.device != "" {
			device = &c.device
		}
		b.Queue(`INSERT INTO openpicket.syslog_sources (addr, device_id, messages, dropped, sample, last_seen) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (addr) DO UPDATE SET device_id = excluded.device_id, messages = syslog_sources.messages + excluded.messages,
				dropped = syslog_sources.dropped + excluded.dropped, sample = excluded.sample, last_seen = excluded.last_seen`,
			addr, device, c.messages, c.dropped, c.sample, c.last)
	}
	if err := s.db.SendBatch(ctx, b).Close(); err != nil {
		s.log.Warn("record syslog senders", "err", err)
	}
}
