// Package opensearch indexes log records into OpenSearch data streams
// (docs/ARCHITECTURE.md §4.8), after the acknowledgement and best effort:
// openpicket-eve-<event_type>, openpicket-nflog, openpicket-<type> for text
// logs, and openpicket-crowdsec-alerts for the LAPI alerts.
//
// Documents use the record id as _id, so a retransmitted record is a
// version conflict that is ignored: duplicates cannot appear.
package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/pkg/record"
)

// Config configures the sink.
type Config struct {
	// URL of the cluster (https://opensearch:9200).
	URL      string
	Username string
	Password string
	CAFile   string
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
	// Prefix of the data streams (default "openpicket").
	Prefix string
	// Retention deletes backing indices older than this (ISM, default 30d).
	Retention time.Duration
	// Replicas of the backing indices (default 1).
	Replicas   int
	Timeout    time.Duration
	HTTPClient *http.Client
}

// Client talks to OpenSearch.
type Client struct {
	cfg  Config
	http *http.Client
}

// New creates a client.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("opensearch: URL is required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.Prefix == "" {
		cfg.Prefix = "openpicket"
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	if cfg.Replicas < 0 {
		cfg.Replicas = 0
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	c := &Client{cfg: cfg, http: cfg.HTTPClient}
	if c.http == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // opt-in
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("opensearch: no certificates in CA file")
			}
			tc.RootCAs = pool
		}
		tr.TLSClientConfig = tc
		c.http = &http.Client{Transport: tr}
	}
	return c, nil
}

// Name implements pipeline.Sink.
func (c *Client) Name() string { return "opensearch" }

func (c *Client) do(ctx context.Context, method, path string, body []byte, ctype string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out, err
}

var nameRe = regexp.MustCompile(`[^a-z0-9_-]+`)

// Stream returns the data stream of a record.
func (c *Client) Stream(b *pipeline.Batch, r *pipeline.Record) string {
	switch b.Type {
	case record.TypeEve:
		t := nameRe.ReplaceAllString(strings.ToLower(r.EventType), "_")
		if t == "" {
			t = "unknown"
		}
		return c.cfg.Prefix + "-eve-" + t
	case record.TypeNflog:
		return c.cfg.Prefix + "-nflog"
	}
	return c.cfg.Prefix + "-" + nameRe.ReplaceAllString(b.Type, "_")
}

// Doc returns the document of a record: the JSON line (or the text line as
// "message") with @timestamp and the manager's enrichment.
func Doc(b *pipeline.Batch, r *pipeline.Record) []byte {
	meta := map[string]any{"node_id": b.NodeID, "boot_id": b.BootID, "log_type": b.Type, "ingest_ts": b.Received.UTC().Format(time.RFC3339Nano)}
	if b.Instance != "" {
		meta["instance"] = b.Instance
	}
	if b.Node != nil {
		if s := b.Node.Site(); s != "" {
			meta["site"] = s
		}
		if len(b.Node.Labels) > 0 {
			meta["labels"] = b.Node.Labels
		}
	}
	if r.SrcGeo != nil {
		meta["src_geo"] = r.SrcGeo
	}
	if r.DestGeo != nil {
		meta["dest_geo"] = r.DestGeo
	}
	ts := r.Time.UTC().Format(time.RFC3339Nano)
	var line []byte
	if r.Eve != nil && record.IsJSON(b.Type) && json.Valid(r.Line) {
		line = r.Line
	} else {
		line, _ = json.Marshal(map[string]string{"message": string(r.Line)})
	}
	line = record.AppendField(line, "@timestamp", ts)
	return record.AppendField(line, "openpicket_meta", meta)
}

// bulkResponse is the part of a _bulk answer we read.
type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		Status int `json:"status"`
		Error  *struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	} `json:"items"`
}

// bulkState remembers documents already indexed across retries.
type bulkState struct {
	done map[int]bool
}

// Deliver implements pipeline.Sink.
func (c *Client) Deliver(ctx context.Context, b *pipeline.Batch) error {
	st := b.State(c.Name(), func() any { return &bulkState{done: map[int]bool{}} }).(*bulkState)
	var body bytes.Buffer
	var idx []int
	for i, r := range b.Records {
		if st.done[i] {
			continue
		}
		action, _ := json.Marshal(map[string]map[string]string{"create": {"_index": c.Stream(b, r), "_id": r.RID}})
		body.Write(action)
		body.WriteByte('\n')
		body.Write(Doc(b, r))
		body.WriteByte('\n')
		idx = append(idx, i)
	}
	if len(idx) == 0 {
		return nil
	}
	retry, err := c.bulk(ctx, body.Bytes(), func(i int) { st.done[idx[i]] = true })
	if err != nil {
		return err
	}
	if retry > 0 {
		return fmt.Errorf("opensearch: %d documents to retry", retry)
	}
	return nil
}

// bulk sends a _bulk body; done is called for every item that needs no
// retry (created, duplicate, or rejected for good). It returns how many
// items must be retried.
func (c *Client) bulk(ctx context.Context, body []byte, done func(i int)) (int, error) {
	code, out, err := c.do(ctx, http.MethodPost, "/_bulk", body, "application/x-ndjson")
	if err != nil {
		return 0, err
	}
	switch {
	case code == http.StatusTooManyRequests || code >= 500:
		return 0, fmt.Errorf("opensearch bulk: status %d", code)
	case code >= 300:
		return 0, fmt.Errorf("%w: opensearch bulk: status %d: %s", pipeline.ErrPermanent, code, truncate(out))
	}
	var res bulkResponse
	if err := json.Unmarshal(out, &res); err != nil {
		return 0, fmt.Errorf("opensearch bulk: %w", err)
	}
	retry := 0
	for i, item := range res.Items {
		for _, r := range item {
			switch {
			case r.Status < 300, r.Status == http.StatusConflict:
				// Created, or the record is already there (retransmission).
				done(i)
			case r.Status == http.StatusTooManyRequests || r.Status >= 500:
				retry++
			default:
				// Mapping conflicts and the like: retrying cannot help.
				done(i)
			}
		}
	}
	return retry, nil
}

func truncate(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

// IndexAlerts indexes LAPI alerts (documents keyed by instance and id).
func (c *Client) IndexAlerts(ctx context.Context, docs []AlertDoc) error {
	if len(docs) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, d := range docs {
		action, _ := json.Marshal(map[string]map[string]string{"create": {"_index": c.cfg.Prefix + "-crowdsec-alerts", "_id": d.ID}})
		body.Write(action)
		body.WriteByte('\n')
		body.Write(d.Doc)
		body.WriteByte('\n')
	}
	retry, err := c.bulk(ctx, body.Bytes(), func(int) {})
	if err != nil {
		return err
	}
	if retry > 0 {
		return fmt.Errorf("opensearch: %d alerts to retry", retry)
	}
	return nil
}

// AlertDoc is one alert document.
type AlertDoc struct {
	ID  string
	Doc []byte
}

// Setup applies the index template and the retention policy (idempotent;
// run by one replica).
func (c *Client) Setup(ctx context.Context) error {
	tpl := map[string]any{
		"index_patterns": []string{c.cfg.Prefix + "-*"},
		"data_stream":    map[string]any{},
		"priority":       200,
		"template": map[string]any{
			"settings": map[string]any{"number_of_shards": 1, "number_of_replicas": c.cfg.Replicas, "index.mapping.total_fields.limit": 5000},
			"mappings": map[string]any{
				"dynamic_templates": []any{
					map[string]any{"ips": map[string]any{"match_pattern": "regex", "match": "^(src_ip|dest_ip|remote_ip|local_ip|ip)$",
						"mapping": map[string]any{"type": "ip", "ignore_malformed": true}}},
					map[string]any{"strings": map[string]any{"match_mapping_type": "string",
						"mapping": map[string]any{"type": "keyword", "ignore_above": 1024}}},
				},
				"properties": map[string]any{
					"@timestamp": map[string]any{"type": "date"},
					"message":    map[string]any{"type": "text"},
					"dest_port":  map[string]any{"type": "integer"},
					"src_port":   map[string]any{"type": "integer"},
				},
			},
		},
	}
	raw, _ := json.Marshal(tpl)
	code, out, err := c.do(ctx, http.MethodPut, "/_index_template/"+c.cfg.Prefix, raw, "application/json")
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("opensearch: index template: status %d: %s", code, truncate(out))
	}
	return c.setupISM(ctx)
}

func (c *Client) setupISM(ctx context.Context) error {
	days := int(c.cfg.Retention.Hours()/24 + 0.5)
	if days < 1 {
		days = 1
	}
	policy := map[string]any{"policy": map[string]any{
		"description":   "OpenPicket log retention",
		"default_state": "hot",
		"states": []any{
			map[string]any{"name": "hot", "actions": []any{},
				"transitions": []any{map[string]any{"state_name": "delete", "conditions": map[string]any{"min_index_age": fmt.Sprintf("%dd", days)}}}},
			map[string]any{"name": "delete", "actions": []any{map[string]any{"delete": map[string]any{}}}, "transitions": []any{}},
		},
		"ism_template": []any{map[string]any{"index_patterns": []string{".ds-" + c.cfg.Prefix + "-*"}, "priority": 100}},
	}}
	path := "/_plugins/_ism/policies/" + c.cfg.Prefix + "-retention"
	code, out, err := c.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	query := ""
	if code == http.StatusOK {
		var cur struct {
			SeqNo       int64 `json:"_seq_no"`
			PrimaryTerm int64 `json:"_primary_term"`
			Policy      struct {
				States []struct {
					Transitions []struct {
						Conditions map[string]string `json:"conditions"`
					} `json:"transitions"`
				} `json:"states"`
			} `json:"policy"`
		}
		if json.Unmarshal(out, &cur) == nil && len(cur.Policy.States) > 0 && len(cur.Policy.States[0].Transitions) > 0 &&
			cur.Policy.States[0].Transitions[0].Conditions["min_index_age"] == fmt.Sprintf("%dd", days) {
			return nil
		}
		query = fmt.Sprintf("?if_seq_no=%d&if_primary_term=%d", cur.SeqNo, cur.PrimaryTerm)
	}
	raw, _ := json.Marshal(policy)
	code, out, err = c.do(ctx, http.MethodPut, path+query, raw, "application/json")
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("opensearch: ISM policy: status %d: %s", code, truncate(out))
	}
	return nil
}

// Health returns the cluster status (green, yellow, red).
func (c *Client) Health(ctx context.Context) (string, error) {
	code, out, err := c.do(ctx, http.MethodGet, "/_cluster/health", nil, "")
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("status %d", code)
	}
	var h struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &h); err != nil {
		return "", err
	}
	return h.Status, nil
}
