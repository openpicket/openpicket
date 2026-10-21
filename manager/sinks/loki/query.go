package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entry is one log line returned by a query.
type Entry struct {
	Time time.Time
	Line string
	// Labels are the stream labels with the structured metadata.
	Labels map[string]string
}

// Querier queries Loki (the log explorer).
type Querier struct {
	base   *url.URL
	cfg    Config
	client *http.Client
}

// NewQuerier creates a querier. queryURL is the Loki read endpoint (query
// frontend or gateway); empty uses the push URL's host.
func NewQuerier(cfg Config, queryURL string) (*Querier, error) {
	raw := queryURL
	if raw == "" {
		raw = cfg.URL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("loki: invalid query URL %q", raw)
	}
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/loki/api/v1/push"), "/")
	if cfg.TenantID == "" {
		cfg.TenantID = "openpicket"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	q := &Querier{base: u, cfg: cfg, client: cfg.HTTPClient}
	if q.client == nil {
		q.client = &http.Client{}
	}
	return q, nil
}

func (q *Querier) get(ctx context.Context, path string, params url.Values, out any) error {
	ctx, cancel := context.WithTimeout(ctx, q.cfg.Timeout)
	defer cancel()
	u := *q.base
	u.Path += path
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Scope-OrgID", q.cfg.TenantID)
	if q.cfg.Username != "" {
		req.SetBasicAuth(q.cfg.Username, q.cfg.Password)
	}
	resp, err := q.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &QueryError{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg))}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// QueryError is an error answered by Loki (400: invalid LogQL).
type QueryError struct {
	Status  int
	Message string
}

func (e *QueryError) Error() string { return fmt.Sprintf("loki %d: %s", e.Status, e.Message) }

// QueryRange runs a log query. backward returns the newest lines first.
func (q *Querier) QueryRange(ctx context.Context, logql string, start, end time.Time, limit int, backward bool) ([]Entry, error) {
	dir := "forward"
	if backward {
		dir = "backward"
	}
	params := url.Values{"query": {logql}, "start": {strconv.FormatInt(start.UnixNano(), 10)}, "end": {strconv.FormatInt(end.UnixNano(), 10)},
		"limit": {strconv.Itoa(limit)}, "direction": {dir}}
	var res struct {
		Data struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][]any           `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := q.get(ctx, "/loki/api/v1/query_range", params, &res); err != nil {
		return nil, err
	}
	if res.Data.ResultType != "streams" {
		return nil, &QueryError{Status: 400, Message: "only log queries are supported (got " + res.Data.ResultType + ")"}
	}
	var out []Entry
	for _, s := range res.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			tsStr, _ := v[0].(string)
			line, _ := v[1].(string)
			ns, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				continue
			}
			labels := make(map[string]string, len(s.Stream))
			for k, val := range s.Stream {
				labels[k] = val
			}
			if len(v) > 2 {
				if md, ok := v[2].(map[string]any); ok {
					for _, group := range md {
						if g, ok := group.(map[string]any); ok {
							for k, val := range g {
								if sv, ok := val.(string); ok {
									labels[k] = sv
								}
							}
						}
					}
				}
			}
			out = append(out, Entry{Time: time.Unix(0, ns), Line: line, Labels: labels})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if backward {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].Time.Before(out[j].Time)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// LabelValues lists the values of a label in a time range.
func (q *Querier) LabelValues(ctx context.Context, label string, start, end time.Time) ([]string, error) {
	var res struct {
		Data []string `json:"data"`
	}
	params := url.Values{"start": {strconv.FormatInt(start.UnixNano(), 10)}, "end": {strconv.FormatInt(end.UnixNano(), 10)}}
	if err := q.get(ctx, "/loki/api/v1/label/"+url.PathEscape(label)+"/values", params, &res); err != nil {
		return nil, err
	}
	return res.Data, nil
}

// Ready checks Loki's readiness endpoint.
func (q *Querier) Ready(ctx context.Context) error {
	var v any
	err := q.get(ctx, "/loki/api/v1/labels", url.Values{"start": {strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10)}}, &v)
	return err
}

// Quote returns a LogQL string literal.
func Quote(s string) string { return strconv.Quote(s) }
