// Package crowdsec forwards detection-relevant records to the CrowdSec log
// processors through their HTTP datasource (NDJSON, gzip;
// docs/ARCHITECTURE.md §4.2).
//
// Records are sharded by openpicket.remote_ip — the groupby key of the
// OpenPicket scenarios — with rendezvous hashing, so every manager replica
// sends the same remote address to the same log processor and leaky
// buckets work. An unhealthy log processor is skipped for a while; only its
// share of addresses moves to the remaining ones.
package crowdsec

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/pkg/record"
)

// Config configures the sink.
type Config struct {
	// Endpoints are log processor base URLs (http://lp-0.lp:8081). Ignored
	// when DiscoveryHost is set.
	Endpoints []string
	// DiscoveryHost is a DNS name resolving to every log processor (a
	// headless Service); endpoints are scheme://<ip>:DiscoveryPort.
	DiscoveryHost   string
	DiscoveryPort   int
	DiscoveryScheme string
	// EvePath and NflogPath are the datasource paths (default /openpicket
	// for both; the parsers tell records apart by event_type).
	EvePath   string
	NflogPath string
	// AuthHeader/AuthValue authenticate to the datasource (auth_type: headers).
	AuthHeader string
	AuthValue  string
	// EveTypes are the eve event types sent (default alert, anomaly).
	EveTypes []string
	// NflogPrefixes are the nflog prefixes sent (default DNAT-MISS).
	NflogPrefixes []string
	// DownFor is how long a failed endpoint is skipped (default 30s).
	DownFor    time.Duration
	Timeout    time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
	// Resolve looks up DiscoveryHost (tests); default net.DefaultResolver.
	Resolve func(ctx context.Context, host string) ([]string, error)
}

// Sink sends records to CrowdSec.
type Sink struct {
	cfg    Config
	client *http.Client
	log    *slog.Logger

	mu        sync.Mutex
	endpoints []string
	downUntil map[string]time.Time
}

// New creates the sink. With discovery, call Run to refresh endpoints.
func New(cfg Config) (*Sink, error) {
	if cfg.DiscoveryHost == "" && len(cfg.Endpoints) == 0 {
		return nil, errors.New("crowdsec: endpoints or discovery host required")
	}
	if cfg.EvePath == "" {
		cfg.EvePath = "/openpicket"
	}
	if cfg.NflogPath == "" {
		cfg.NflogPath = "/openpicket"
	}
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = "X-OpenPicket-Token"
	}
	if len(cfg.EveTypes) == 0 {
		cfg.EveTypes = []string{"alert", "anomaly"}
	}
	if len(cfg.NflogPrefixes) == 0 {
		cfg.NflogPrefixes = []string{"DNAT-MISS"}
	}
	if cfg.DownFor <= 0 {
		cfg.DownFor = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.DiscoveryScheme == "" {
		cfg.DiscoveryScheme = "http"
	}
	if cfg.DiscoveryPort == 0 {
		cfg.DiscoveryPort = 8081
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Resolve == nil {
		cfg.Resolve = net.DefaultResolver.LookupHost
	}
	s := &Sink{cfg: cfg, client: cfg.HTTPClient, log: cfg.Logger.With("component", "crowdsec-sink"), downUntil: map[string]time.Time{}}
	if s.client == nil {
		s.client = &http.Client{}
	}
	for _, e := range cfg.Endpoints {
		u, err := url.Parse(e)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("crowdsec: invalid endpoint %q", e)
		}
		s.endpoints = append(s.endpoints, strings.TrimRight(e, "/"))
	}
	slices.Sort(s.endpoints)
	return s, nil
}

// Name implements pipeline.Sink.
func (s *Sink) Name() string { return "crowdsec" }

// Run refreshes discovered endpoints until ctx is cancelled.
func (s *Sink) Run(ctx context.Context) {
	if s.cfg.DiscoveryHost == "" {
		return
	}
	for {
		s.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func (s *Sink) refresh(ctx context.Context) {
	addrs, err := s.cfg.Resolve(ctx, s.cfg.DiscoveryHost)
	if err != nil {
		s.log.Warn("discover log processors", "host", s.cfg.DiscoveryHost, "err", err)
		return
	}
	eps := make([]string, 0, len(addrs))
	for _, a := range addrs {
		eps = append(eps, fmt.Sprintf("%s://%s", s.cfg.DiscoveryScheme, net.JoinHostPort(a, fmt.Sprint(s.cfg.DiscoveryPort))))
	}
	slices.Sort(eps)
	s.mu.Lock()
	if !slices.Equal(eps, s.endpoints) {
		s.log.Info("log processors", "endpoints", eps)
	}
	s.endpoints = eps
	s.mu.Unlock()
}

// Health returns the number of endpoints and of those not marked down.
func (s *Sink) Health() (total, up int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	for _, e := range s.endpoints {
		if now.After(s.downUntil[e]) {
			up++
		}
	}
	return len(s.endpoints), up
}

// healthy returns the endpoints not marked down (all when every one is).
func (s *Sink) healthy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	var up []string
	for _, e := range s.endpoints {
		if now.After(s.downUntil[e]) {
			up = append(up, e)
		}
	}
	if len(up) == 0 {
		// Everything is marked down: try all rather than none.
		up = append(up, s.endpoints...)
	}
	return up
}

func (s *Sink) markDown(e string) {
	s.mu.Lock()
	s.downUntil[e] = s.cfg.Now().Add(s.cfg.DownFor)
	s.mu.Unlock()
}

// Pick returns the rendezvous choice of key among endpoints.
func Pick(key string, endpoints []string) string {
	var (
		best  string
		score uint64
	)
	for _, e := range endpoints {
		h := fnv.New64a()
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(e))
		if v := h.Sum64(); best == "" || v > score {
			best, score = e, v
		}
	}
	return best
}

// selected reports whether a record goes to CrowdSec and its path.
func (s *Sink) selected(b *pipeline.Batch, r *pipeline.Record) (string, bool) {
	if r.Eve == nil {
		return "", false
	}
	switch b.Type {
	case record.TypeEve:
		return s.cfg.EvePath, slices.Contains(s.cfg.EveTypes, r.EventType)
	case record.TypeNflog:
		return s.cfg.NflogPath, slices.Contains(s.cfg.NflogPrefixes, r.Eve.Prefix)
	}
	return "", false
}

// shardKey is the scenarios' groupby key.
func shardKey(r *pipeline.Record) string {
	if t := r.Eve.OpenPicket; t != nil && t.RemoteIP != "" {
		return t.RemoteIP
	}
	return r.Eve.SrcIP
}

// meta is appended to each record as "openpicket_meta".
type meta struct {
	// TS is the event time in RFC 3339 (eve's "+0900" offsets are not
	// parsed by CrowdSec's dateparse-enrich).
	TS       string            `json:"ts"`
	NodeID   string            `json:"node_id"`
	Site     string            `json:"site,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	IngestTS string            `json:"ingest_ts"`
	SrcGeo   *pipeline.Geo     `json:"src_geo,omitempty"`
	DestGeo  *pipeline.Geo     `json:"dest_geo,omitempty"`
	// RemoteGeo is the geo of openpicket.remote_ip (the address scenarios
	// act on); the parsers copy it into the alert source.
	RemoteGeo *pipeline.Geo `json:"remote_geo,omitempty"`
}

// Line returns the NDJSON line sent for a record.
func Line(b *pipeline.Batch, r *pipeline.Record) []byte {
	m := meta{TS: r.Time.UTC().Format(time.RFC3339Nano), NodeID: b.NodeID, IngestTS: b.Received.UTC().Format(time.RFC3339Nano), SrcGeo: r.SrcGeo, DestGeo: r.DestGeo}
	if b.Node != nil {
		m.Site, m.Labels = b.Node.Site(), b.Node.Labels
	}
	if r.Eve != nil && r.Eve.OpenPicket != nil {
		switch r.Eve.OpenPicket.RemoteIP {
		case "":
		case r.Eve.SrcIP:
			m.RemoteGeo = r.SrcGeo
		case r.Eve.DestIP:
			m.RemoteGeo = r.DestGeo
		}
	}
	return record.AppendField(r.Line, "openpicket_meta", m)
}

// progress tracks the records of a batch already accepted, across retries.
type progress struct {
	mu   sync.Mutex
	done map[int]bool
}

// Deliver implements pipeline.Sink. Records already accepted by a log
// processor in an earlier attempt are not sent again.
func (s *Sink) Deliver(ctx context.Context, b *pipeline.Batch) error {
	pr := b.State(s.Name(), func() any { return &progress{done: map[int]bool{}} }).(*progress)
	up := s.healthy()
	if len(up) == 0 {
		return errors.New("crowdsec: no log processor endpoints")
	}
	type group struct {
		endpoint, path string
		idx            []int
		body           bytes.Buffer
	}
	groups := map[string]*group{}
	var keys []string
	pr.mu.Lock()
	for i, r := range b.Records {
		if pr.done[i] {
			continue
		}
		path, ok := s.selected(b, r)
		if !ok {
			continue
		}
		ep := Pick(shardKey(r), up)
		k := ep + path
		g, ok := groups[k]
		if !ok {
			g = &group{endpoint: ep, path: path}
			groups[k] = g
			keys = append(keys, k)
		}
		g.idx = append(g.idx, i)
		g.body.Write(Line(b, r))
		g.body.WriteByte('\n')
	}
	pr.mu.Unlock()
	var errs []error
	permanent := false
	for _, k := range keys {
		g := groups[k]
		if err := s.post(ctx, g.endpoint+g.path, g.body.Bytes()); err != nil {
			if errors.Is(err, pipeline.ErrPermanent) {
				// The datasource refused the data itself; another
				// attempt would fail the same way.
				permanent = true
			} else {
				s.markDown(g.endpoint)
			}
			errs = append(errs, fmt.Errorf("%s: %w", g.endpoint, err))
			continue
		}
		pr.mu.Lock()
		for _, i := range g.idx {
			pr.done[i] = true
		}
		pr.mu.Unlock()
	}
	if err := errors.Join(errs...); err != nil {
		if permanent {
			return fmt.Errorf("%w: %v", pipeline.ErrPermanent, err)
		}
		return err
	}
	return nil
}

func (s *Sink) post(ctx context.Context, u string, ndjson []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(ndjson)
	_ = zw.Close()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	if s.cfg.AuthHeader != "" {
		req.Header.Set(s.cfg.AuthHeader, s.cfg.AuthValue)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge {
			return fmt.Errorf("%w: %v", pipeline.ErrPermanent, err)
		}
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
