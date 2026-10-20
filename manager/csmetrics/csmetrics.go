// Package csmetrics scrapes the Prometheus endpoints of CrowdSec agents and
// LAPIs and summarizes them as cscli metrics does: acquisition, parsers,
// scenarios, LAPI routes, machines and bouncers, decisions, AppSec,
// whitelists and latencies.
package csmetrics

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
)

// Config configures the scraper.
type Config struct {
	// URLs of metrics endpoints (http://crowdsec-lapi:6060/metrics).
	URLs []string
	// DiscoveryHost resolves to agent pods (headless service); each
	// address is scraped on DiscoveryPort (default 6060).
	DiscoveryHost string
	DiscoveryPort int
	Timeout       time.Duration
	// CacheTTL of a scrape (default 10s).
	CacheTTL   time.Duration
	HTTPClient *http.Client
	Resolve    func(ctx context.Context, host string) ([]string, error)
}

// Scraper scrapes and caches.
type Scraper struct {
	cfg    Config
	client *http.Client

	mu     sync.Mutex
	cached map[string]*apiv1.GetCrowdSecMetricsResponse
	at     map[string]time.Time
}

// New creates a scraper.
func New(cfg Config) *Scraper {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Second
	}
	if cfg.DiscoveryPort == 0 {
		cfg.DiscoveryPort = 6060
	}
	if cfg.Resolve == nil {
		cfg.Resolve = net.DefaultResolver.LookupHost
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{}
	}
	return &Scraper{cfg: cfg, client: c, cached: map[string]*apiv1.GetCrowdSecMetricsResponse{}, at: map[string]time.Time{}}
}

// Configured reports whether any endpoint is configured.
func (s *Scraper) Configured() bool { return len(s.cfg.URLs) > 0 || s.cfg.DiscoveryHost != "" }

type endpoint struct{ name, url string }

func (s *Scraper) endpoints(ctx context.Context) ([]endpoint, error) {
	var out []endpoint
	for _, raw := range s.cfg.URLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("csmetrics: invalid URL %q", raw)
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = "/metrics"
		}
		out = append(out, endpoint{name: u.Host, url: u.String()})
	}
	if s.cfg.DiscoveryHost != "" {
		addrs, err := s.cfg.Resolve(ctx, s.cfg.DiscoveryHost)
		if err != nil {
			return out, fmt.Errorf("csmetrics: resolve %s: %w", s.cfg.DiscoveryHost, err)
		}
		sort.Strings(addrs)
		for _, a := range addrs {
			hp := net.JoinHostPort(a, strconv.Itoa(s.cfg.DiscoveryPort))
			out = append(out, endpoint{name: hp, url: "http://" + hp + "/metrics"})
		}
	}
	return out, nil
}

type families map[string]*dto.MetricFamily

func (s *Scraper) scrape(ctx context.Context, e endpoint) (families, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	p := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := p.TextToMetricFamilies(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return fams, nil
}

// Get scrapes (or returns the cached result for) one endpoint or all.
func (s *Scraper) Get(ctx context.Context, only string) (*apiv1.GetCrowdSecMetricsResponse, error) {
	s.mu.Lock()
	if r, ok := s.cached[only]; ok && time.Since(s.at[only]) < s.cfg.CacheTTL {
		s.mu.Unlock()
		return r, nil
	}
	s.mu.Unlock()
	eps, err := s.endpoints(ctx)
	if err != nil && len(eps) == 0 {
		return nil, err
	}
	res := &apiv1.GetCrowdSecMetricsResponse{ScrapedAt: timestamppb.Now(), Partial: err != nil}
	var all []families
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]*apiv1.MetricsEndpoint, len(eps))
	for i, e := range eps {
		results[i] = &apiv1.MetricsEndpoint{Name: e.name, Url: e.url}
		if only != "" && e.name != only {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fams, err := s.scrape(ctx, e)
			if err != nil {
				results[i].Error = err.Error()
				return
			}
			results[i].Ok = true
			if f := fams["cs_info"]; f != nil && len(f.Metric) > 0 {
				results[i].Version = label(f.Metric[0], "version")
			}
			mu.Lock()
			all = append(all, fams)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, r := range results {
		if only != "" && r.Name != only {
			continue
		}
		res.Endpoints = append(res.Endpoints, r)
		if !r.Ok {
			res.Partial = true
		}
	}
	if only != "" && len(res.Endpoints) == 0 {
		return nil, fmt.Errorf("csmetrics: unknown endpoint %q", only)
	}
	res.Tables = Tables(all)
	s.mu.Lock()
	s.cached[only], s.at[only] = res, time.Now()
	s.mu.Unlock()
	return res, nil
}

func label(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func value(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	case m.Untyped != nil:
		return m.Untyped.GetValue()
	}
	return 0
}

// table accumulates rows keyed by label values.
type table struct {
	name, title string
	keys        []string // key column names
	cols        []string // value column names
	rows        map[string][]float64
	keyVals     map[string][]string
}

func newTable(name, title string, keys, cols []string) *table {
	return &table{name: name, title: title, keys: keys, cols: cols, rows: map[string][]float64{}, keyVals: map[string][]string{}}
}

func (t *table) add(keyVals []string, col int, v float64) {
	k := strings.Join(keyVals, "\x00")
	r, ok := t.rows[k]
	if !ok {
		r = make([]float64, len(t.cols))
		t.rows[k] = r
		t.keyVals[k] = keyVals
	}
	r[col] += v
}

// sum adds every series of metric to column col, keyed by labels.
func (t *table) sum(all []families, metric string, labels []string, col int) {
	for _, fams := range all {
		f := fams[metric]
		if f == nil {
			continue
		}
		for _, m := range f.Metric {
			kv := make([]string, len(labels))
			for i, l := range labels {
				kv[i] = label(m, l)
			}
			t.add(kv, col, value(m))
		}
	}
}

func format(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 3, 64)
}

func (t *table) build() *apiv1.MetricsTable {
	out := &apiv1.MetricsTable{Name: t.name, Title: t.title, Columns: append(slices.Clone(t.keys), t.cols...)}
	keys := make([]string, 0, len(t.rows))
	for k := range t.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cells := slices.Clone(t.keyVals[k])
		for _, v := range t.rows[k] {
			cells = append(cells, format(v))
		}
		out.Rows = append(out.Rows, &apiv1.MetricsRow{Cells: cells})
	}
	return out
}

// histogram summarizes a histogram per label set: count, average and an
// estimated 95th percentile (upper bound of the bucket).
func histogram(all []families, metric, name, title string, labels []string) *apiv1.MetricsTable {
	type acc struct {
		count, sum float64
		buckets    map[float64]float64
	}
	accs := map[string]*acc{}
	kvs := map[string][]string{}
	for _, fams := range all {
		f := fams[metric]
		if f == nil {
			continue
		}
		for _, m := range f.Metric {
			h := m.Histogram
			if h == nil {
				continue
			}
			kv := make([]string, len(labels))
			for i, l := range labels {
				kv[i] = label(m, l)
			}
			k := strings.Join(kv, "\x00")
			a := accs[k]
			if a == nil {
				a = &acc{buckets: map[float64]float64{}}
				accs[k], kvs[k] = a, kv
			}
			a.count += float64(h.GetSampleCount())
			a.sum += h.GetSampleSum()
			for _, b := range h.Bucket {
				a.buckets[b.GetUpperBound()] += float64(b.GetCumulativeCount())
			}
		}
	}
	out := &apiv1.MetricsTable{Name: name, Title: title, Columns: append(slices.Clone(labels), "count", "avg_ms", "p95_ms")}
	keys := make([]string, 0, len(accs))
	for k := range accs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := accs[k]
		avg, p95 := 0.0, 0.0
		if a.count > 0 {
			avg = a.sum / a.count * 1000
			bounds := make([]float64, 0, len(a.buckets))
			for b := range a.buckets {
				bounds = append(bounds, b)
			}
			sort.Float64s(bounds)
			for _, b := range bounds {
				if a.buckets[b] >= 0.95*a.count {
					p95 = b * 1000
					break
				}
			}
			if math.IsInf(p95, 1) {
				p95 = -1
			}
		}
		p := format(p95)
		if p95 < 0 {
			p = "> max bucket"
		}
		out.Rows = append(out.Rows, &apiv1.MetricsRow{Cells: append(slices.Clone(kvs[k]), format(a.count), format(avg), p)})
	}
	return out
}

// Tables builds the cscli-style tables from scraped families (summed over
// endpoints). Empty tables are left out.
func Tables(all []families) []*apiv1.MetricsTable {
	var out []*apiv1.MetricsTable
	keep := func(t *apiv1.MetricsTable) {
		if len(t.Rows) > 0 {
			out = append(out, t)
		}
	}
	// Acquisition: any cs_*source_hits_total is "lines read".
	acq := newTable("acquisition", "Acquisition", []string{"source", "type"}, []string{"read", "parsed", "unparsed", "poured"})
	for _, fams := range all {
		for name := range fams {
			if strings.HasPrefix(name, "cs_") && strings.HasSuffix(name, "source_hits_total") {
				acq.sum([]families{fams}, name, []string{"src", "datasource_type"}, 0)
				acq.sum([]families{fams}, name, []string{"source", "type"}, 0)
			}
		}
	}
	// File sources label "source", HTTP ones "src": drop the empty rows the
	// double pass created.
	for k, kv := range acq.keyVals {
		if kv[0] == "" {
			delete(acq.rows, k)
			delete(acq.keyVals, k)
		}
	}
	acq.sum(all, "cs_parser_hits_ok_total", []string{"source", "type"}, 1)
	acq.sum(all, "cs_parser_hits_ko_total", []string{"source", "type"}, 2)
	acq.sum(all, "cs_bucket_poured_total", []string{"source", "type"}, 3)
	keep(acq.build())

	parsers := newTable("parsers", "Parsers", []string{"parser"}, []string{"hits", "parsed", "unparsed"})
	parsers.sum(all, "cs_node_hits_total", []string{"name"}, 0)
	parsers.sum(all, "cs_node_hits_ok_total", []string{"name"}, 1)
	parsers.sum(all, "cs_node_hits_ko_total", []string{"name"}, 2)
	keep(parsers.build())

	sc := newTable("scenarios", "Scenarios", []string{"scenario"}, []string{"current", "overflowed", "instantiated", "poured", "expired"})
	sc.sum(all, "cs_buckets", []string{"name"}, 0)
	sc.sum(all, "cs_bucket_overflowed_total", []string{"name"}, 1)
	sc.sum(all, "cs_bucket_instantiation_total", []string{"name"}, 2)
	sc.sum(all, "cs_bucket_poured_total", []string{"name"}, 3)
	sc.sum(all, "cs_bucket_underflowed_total", []string{"name"}, 4)
	keep(sc.build())

	wl := newTable("whitelists", "Whitelists", []string{"whitelist", "reason"}, []string{"hits", "whitelisted"})
	wl.sum(all, "cs_node_wl_hits_total", []string{"name", "reason"}, 0)
	wl.sum(all, "cs_node_wl_hits_ok_total", []string{"name", "reason"}, 1)
	keep(wl.build())

	lapi := newTable("lapi", "Local API", []string{"route", "method"}, []string{"hits"})
	lapi.sum(all, "cs_lapi_route_requests_total", []string{"route", "method"}, 0)
	keep(lapi.build())

	machines := newTable("lapi_machines", "Local API machines", []string{"machine", "route", "method"}, []string{"hits"})
	machines.sum(all, "cs_lapi_machine_requests_total", []string{"machine", "route", "method"}, 0)
	keep(machines.build())

	bouncers := newTable("lapi_bouncers", "Local API bouncers", []string{"bouncer", "route", "method"}, []string{"hits"})
	bouncers.sum(all, "cs_lapi_bouncer_requests_total", []string{"bouncer", "route", "method"}, 0)
	keep(bouncers.build())

	pulls := newTable("lapi_decision_pulls", "Bouncer decision pulls", []string{"bouncer"}, []string{"non_empty", "empty"})
	pulls.sum(all, "cs_lapi_decisions_ok_total", []string{"bouncer"}, 0)
	pulls.sum(all, "cs_lapi_decisions_ko_total", []string{"bouncer"}, 1)
	keep(pulls.build())

	dec := newTable("decisions", "Active decisions", []string{"reason", "origin", "action"}, []string{"count"})
	dec.sum(all, "cs_active_decisions", []string{"reason", "origin", "action"}, 0)
	keep(dec.build())

	al := newTable("alerts", "Alerts", []string{"reason"}, []string{"count"})
	al.sum(all, "cs_alerts", []string{"reason"}, 0)
	keep(al.build())

	appsec := newTable("appsec", "AppSec", []string{"engine"}, []string{"processed", "blocked"})
	appsec.sum(all, "cs_appsec_reqs_total", []string{"appsec_engine"}, 0)
	appsec.sum(all, "cs_appsec_block_total", []string{"appsec_engine"}, 1)
	keep(appsec.build())

	rules := newTable("appsec_rules", "AppSec rules", []string{"engine", "rule"}, []string{"triggered"})
	rules.sum(all, "cs_appsec_rule_hits", []string{"appsec_engine", "rule_name"}, 0)
	keep(rules.build())

	keep(histogram(all, "cs_lapi_request_duration_seconds", "lapi_latency", "Local API latency", []string{"endpoint", "method"}))
	keep(histogram(all, "cs_parsing_time_seconds", "parsing_time", "Parsing time", []string{"source", "type"}))
	return out
}
