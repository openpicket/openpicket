// Package loki pushes log batches to Grafana Loki (the raw log archive,
// docs/ARCHITECTURE.md §4.6).
//
// Retransmitted records must land with the same timestamp, labels and line
// so that Loki hides the duplicate at query time: stream labels come only
// from fields fixed in the record (node, type, instance, event_type), the
// line is the record as the agent sent it, and everything that may differ
// between attempts (geo, site, ingest time) is structured metadata.
package loki

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/pkg/record"
)

// Config configures the sink.
type Config struct {
	// URL is the push endpoint, e.g. http://loki-gateway/loki/api/v1/push.
	// A URL without a path gets /loki/api/v1/push.
	URL string
	// TenantID is sent as X-Scope-OrgID (default "openpicket").
	TenantID string
	Username string
	Password string
	// MaxAge mirrors Loki's reject_old_samples_max_age: older records are
	// not sent (default 7 days).
	MaxAge time.Duration
	// FutureGrace mirrors creation_grace_period (default 10 minutes).
	FutureGrace time.Duration
	Timeout     time.Duration
	HTTPClient  *http.Client
	Registerer  prometheus.Registerer
	Now         func() time.Time
}

// Sink pushes to Loki.
type Sink struct {
	cfg      Config
	client   *http.Client
	rejected *prometheus.CounterVec
}

// New creates a Loki sink.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("loki: URL is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("loki: invalid URL %q", cfg.URL)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/loki/api/v1/push"
		cfg.URL = u.String()
	}
	if cfg.TenantID == "" {
		cfg.TenantID = "openpicket"
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 7 * 24 * time.Hour
	}
	if cfg.FutureGrace <= 0 {
		cfg.FutureGrace = 10 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Sink{cfg: cfg, client: cfg.HTTPClient,
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "openpicket_loki_rejected_records_total", Help: "Records not stored in Loki (outside its time window).",
		}, []string{"node", "reason"})}
	if s.client == nil {
		s.client = &http.Client{}
	}
	if cfg.Registerer != nil {
		if err := cfg.Registerer.Register(s.rejected); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Name implements pipeline.Sink.
func (s *Sink) Name() string { return "loki" }

type stream struct {
	Stream map[string]string `json:"stream"`
	Values [][]any           `json:"values"`
}

// Labels returns the stream labels of a record.
func Labels(b *pipeline.Batch, r *pipeline.Record) map[string]string {
	l := map[string]string{"job": "openpicket", "node": b.NodeID, "type": b.Type}
	if b.Instance != "" {
		l["instance"] = b.Instance
	}
	if b.Type == record.TypeEve && r.EventType != "" {
		l["event_type"] = r.EventType
	}
	return l
}

// Metadata returns the structured metadata of a record.
func Metadata(b *pipeline.Batch, r *pipeline.Record) map[string]string {
	m := map[string]string{"ingest_ts": b.Received.UTC().Format(time.RFC3339Nano)}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("rid", r.RID)
	if b.Node != nil {
		set("site", b.Node.Site())
	}
	if e := r.Eve; e != nil {
		set("src_ip", e.SrcIP)
		set("dest_ip", e.DestIP)
		if e.DestPort != 0 {
			m["dest_port"] = strconv.Itoa(e.DestPort)
		}
		set("proto", e.Proto)
		set("community_id", e.CommunityID)
		if e.Alert != nil && e.Alert.SignatureID != 0 {
			m["signature_id"] = strconv.FormatInt(e.Alert.SignatureID, 10)
		}
		if e.TLS != nil {
			set("ja4", e.TLS.JA4)
		}
		if t := e.OpenPicket; t != nil {
			set("direction", t.Direction)
			set("remote_ip", t.RemoteIP)
		}
	}
	geo := func(prefix string, g *pipeline.Geo) {
		if g == nil {
			return
		}
		set(prefix+"_cc", g.Country)
		if g.ASN != 0 {
			m[prefix+"_asn"] = strconv.FormatUint(uint64(g.ASN), 10)
		}
	}
	geo("src", r.SrcGeo)
	geo("dest", r.DestGeo)
	return m
}

func labelKey(l map[string]string) string {
	return l["node"] + "\x00" + l["type"] + "\x00" + l["instance"] + "\x00" + l["event_type"]
}

// Deliver implements pipeline.Sink.
func (s *Sink) Deliver(ctx context.Context, b *pipeline.Batch) error {
	now := s.cfg.Now()
	oldest, newest := now.Add(-s.cfg.MaxAge), now.Add(s.cfg.FutureGrace)
	streams := map[string]*stream{}
	var order []string
	for _, r := range b.Records {
		switch {
		case r.Time.Before(oldest):
			s.rejected.WithLabelValues(b.NodeID, "too_old").Inc()
			continue
		case r.Time.After(newest):
			s.rejected.WithLabelValues(b.NodeID, "future").Inc()
			continue
		}
		l := Labels(b, r)
		k := labelKey(l)
		st, ok := streams[k]
		if !ok {
			st = &stream{Stream: l}
			streams[k] = st
			order = append(order, k)
		}
		st.Values = append(st.Values, []any{strconv.FormatInt(r.Time.UnixNano(), 10), string(r.Line), Metadata(b, r)})
	}
	if len(order) == 0 {
		return nil
	}
	body := struct {
		Streams []*stream `json:"streams"`
	}{}
	for _, k := range order {
		body.Streams = append(body.Streams, streams[k])
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(body); err != nil {
		return fmt.Errorf("%w: encode: %v", pipeline.ErrPermanent, err)
	}
	if err := zw.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Scope-OrgID", s.cfg.TenantID)
	if s.cfg.Username != "" {
		req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge:
		// Loki stores the valid entries of a request and reports the
		// others (out of order, too old, too long) with 400. Retrying would
		// not change the outcome.
		s.rejected.WithLabelValues(b.NodeID, "rejected_by_loki").Inc()
		return fmt.Errorf("%w: loki %d: %s", pipeline.ErrPermanent, resp.StatusCode, strings.TrimSpace(string(msg)))
	default:
		return fmt.Errorf("loki %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}
