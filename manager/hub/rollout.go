package hub

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/pkg/hubitem"
)

func newGzip(w io.Writer) *gzip.Writer { return gzip.NewWriter(w) }

// Rollout pushes the content to the log processors, one at a time: a
// reload stops a log processor's datasource for a moment, and a revision
// the first one refuses (crowdsec -t) goes no further. Log processors then
// get the last revision one accepted, so a new one never stays empty.
type Rollout struct {
	Store *Store
	// Targets returns the sync URLs of the log processors
	// (http://<ip>:8082).
	Targets func() []string
	// Header and Token authenticate to them (the datasource token).
	Header, Token string
	Client        *http.Client
	Logger        *slog.Logger
	// Interval between checks without a change (default 30s).
	Interval time.Duration

	poke chan struct{}
}

// Notified wakes the rollout (openpicket_hub).
func (r *Rollout) Notified(string) {
	select {
	case r.poke <- struct{}{}:
	default:
	}
}

// Init must be called before Run and Notified.
func (r *Rollout) Init() {
	r.poke = make(chan struct{}, 1)
	if r.Client == nil {
		r.Client = &http.Client{}
	}
	if r.Logger == nil {
		r.Logger = slog.Default()
	}
	if r.Interval <= 0 {
		r.Interval = 30 * time.Second
	}
}

// Run rolls out until ctx ends (leader task).
func (r *Rollout) Run(ctx context.Context, l *db.Leadership) {
	log := r.Logger.With("component", "hub-rollout")
	for {
		if err := r.pass(ctx, l); err != nil && ctx.Err() == nil {
			log.Warn("content rollout", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.poke:
		case <-time.After(r.Interval):
		}
	}
}

type meta struct {
	revision, good, failed int64
	goodBundle             []byte
}

func (r *Rollout) loadMeta(ctx context.Context) (meta, error) {
	var m meta
	err := r.Store.db.QueryRow(ctx, `SELECT revision, good_revision, COALESCE(good_bundle, ''::bytea), failed_revision FROM openpicket.hub_meta WHERE id = 1`).
		Scan(&m.revision, &m.good, &m.goodBundle, &m.failed)
	return m, err
}

// pass brings every log processor to the target revision, in order.
func (r *Rollout) pass(ctx context.Context, l *db.Leadership) error {
	m, err := r.loadMeta(ctx)
	if err != nil {
		return err
	}
	var candidate []byte // the current revision, built once per pass
	targets := r.Targets()
	for _, ep := range targets {
		st, err := r.status(ctx, ep)
		if err != nil {
			r.record(ctx, l, ep, hubitem.Status{}, "unreachable: "+err.Error())
			continue
		}
		want := m.revision
		if m.failed == m.revision {
			want = m.good
		}
		if want == 0 || (st.Revision == want && st.Running) {
			r.record(ctx, l, ep, st, st.Error)
			continue
		}
		body := m.goodBundle
		if want == m.revision {
			if candidate == nil {
				b, err := r.Store.Bundle(ctx)
				if err != nil {
					return err
				}
				if b.Revision != m.revision {
					// Changed meanwhile: the next pass takes it.
					return nil
				}
				if candidate, err = encodeBundle(b); err != nil {
					return err
				}
			}
			body = candidate
		}
		st, code, err := r.push(ctx, ep, body)
		switch {
		case code == http.StatusUnprocessableEntity && want == m.revision:
			// CrowdSec refused it: the others get the last good one.
			msg := st.Error
			r.Logger.Warn("log processor refused the content; keeping the last accepted revision", "endpoint", ep, "revision", want, "err", msg)
			if err := r.fenced(ctx, l, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE openpicket.hub_meta SET failed_revision = $1, failed_error = $2 WHERE id = 1 AND revision = $1`, want, msg)
				return err
			}); err != nil {
				return err
			}
			m.failed = want
			r.record(ctx, l, ep, st, msg)
		case err != nil:
			r.record(ctx, l, ep, st, err.Error())
		default:
			if want == m.revision && m.good != want {
				if err := r.fenced(ctx, l, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE openpicket.hub_meta SET good_revision = $1, good_bundle = $2 WHERE id = 1 AND good_revision < $1`, want, body)
					return err
				}); err != nil {
					return err
				}
				m.good, m.goodBundle = want, body
				r.Logger.Info("content accepted", "revision", want, "endpoint", ep)
			}
			r.record(ctx, l, ep, st, "")
		}
	}
	// Forget log processors gone for an hour.
	return r.fenced(ctx, l, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM openpicket.hub_lp_state WHERE NOT (endpoint = ANY($1)) AND seen_at < now() - interval '1 hour'`, targets)
		return err
	})
}

func (r *Rollout) fenced(ctx context.Context, l *db.Leadership, fn func(pgx.Tx) error) error {
	if l == nil {
		return pgx.BeginFunc(ctx, r.Store.db, fn)
	}
	return l.Fenced(ctx, fn)
}

func (r *Rollout) record(ctx context.Context, l *db.Leadership, ep string, st hubitem.Status, msg string) {
	err := r.fenced(ctx, l, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_lp_state (endpoint, revision, running, error, seen_at) VALUES ($1,$2,$3,$4,now())
			ON CONFLICT (endpoint) DO UPDATE SET revision=excluded.revision, running=excluded.running, error=excluded.error, seen_at=now()`,
			ep, st.Revision, st.Running, msg)
		return err
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		r.Logger.Debug("record log processor state", "endpoint", ep, "err", err)
	}
}

func (r *Rollout) status(ctx context.Context, ep string) (hubitem.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep+hubitem.PathStatus, nil)
	if err != nil {
		return hubitem.Status{}, err
	}
	req.Header.Set(r.Header, r.Token)
	resp, err := r.Client.Do(req)
	if err != nil {
		return hubitem.Status{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return hubitem.Status{}, fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var st hubitem.Status
	return st, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st)
}

// push sends a bundle and waits until it is applied (or refused).
func (r *Rollout) push(ctx context.Context, ep string, body []byte) (hubitem.Status, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, ep+hubitem.PathBundle, bytes.NewReader(body))
	if err != nil {
		return hubitem.Status{}, 0, err
	}
	req.Header.Set(r.Header, r.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := r.Client.Do(req)
	if err != nil {
		return hubitem.Status{}, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var st hubitem.Status
	if json.Unmarshal(raw, &st) != nil && resp.StatusCode != http.StatusOK {
		return st, resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnprocessableEntity {
		return st, resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	return st, resp.StatusCode, nil
}
