package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunLeader sets up the template and policy, then copies the LAPI alerts
// of the PostgreSQL copy into the alerts data stream, until ctx ends.
// Progress is kept per instance in openpicket.settings.
func (c *Client) RunLeader(ctx context.Context, db *pgxpool.Pool, log *slog.Logger, every time.Duration) {
	backoff := 5 * time.Second
	for {
		err := c.Setup(ctx)
		if err == nil {
			break
		}
		log.Warn("opensearch setup", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := c.exportAlerts(ctx, db); err != nil && ctx.Err() == nil {
			log.Warn("opensearch alert export", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

const alertsKey = "opensearch.alerts.watermark"

func (c *Client) exportAlerts(ctx context.Context, db *pgxpool.Pool) error {
	wm := map[string]int64{}
	var raw []byte
	if err := db.QueryRow(ctx, `SELECT value FROM openpicket.settings WHERE key = $1`, alertsKey).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &wm)
	}
	for {
		wmRaw, _ := json.Marshal(wm)
		rows, err := db.Query(ctx, `SELECT a.instance, a.id, jsonb_build_object(
				'@timestamp', a.created_at, 'instance', a.instance, 'alert_id', a.id, 'uuid', a.uuid, 'scenario', a.scenario,
				'message', a.message, 'source', jsonb_build_object('scope', a.source_scope, 'value', a.source_value, 'ip', NULLIF(a.source_ip, ''),
					'range', a.source_range, 'country', a.country, 'as_number', a.as_number, 'as_name', a.as_name),
				'events_count', a.events_count, 'simulated', a.simulated, 'machine_id', a.machine_id, 'node_id', a.node_id,
				'direction', a.direction, 'start_at', a.start_at, 'stop_at', a.stop_at, 'meta', a.meta,
				'decisions', COALESCE((SELECT jsonb_agg(jsonb_build_object('type', d.type, 'value', d.value, 'origin', d.origin, 'until', d.until))
					FROM openpicket.alert_decisions d WHERE d.instance = a.instance AND d.alert_id = a.id), '[]'))
			FROM openpicket.alerts a WHERE a.id > COALESCE(($1::jsonb ->> a.instance)::bigint, 0) ORDER BY a.id LIMIT 500`, wmRaw)
		if err != nil {
			return err
		}
		var docs []AlertDoc
		next := map[string]int64{}
		for k, v := range wm {
			next[k] = v
		}
		for rows.Next() {
			var (
				inst string
				id   int64
				doc  []byte
			)
			if err := rows.Scan(&inst, &id, &doc); err != nil {
				rows.Close()
				return err
			}
			docs = append(docs, AlertDoc{ID: fmt.Sprintf("%s-%d", inst, id), Doc: doc})
			next[inst] = max(next[inst], id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(docs) == 0 {
			return nil
		}
		if err := c.IndexAlerts(ctx, docs); err != nil {
			return err
		}
		wm = next
		raw, _ := json.Marshal(wm)
		if _, err := db.Exec(ctx, `INSERT INTO openpicket.settings (key, value, updated_at) VALUES ($1,$2,now())
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, alertsKey, raw); err != nil {
			return err
		}
	}
}
