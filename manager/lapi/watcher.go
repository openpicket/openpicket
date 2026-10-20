package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Alert is a LAPI alert (models.Alert).
type Alert struct {
	ID              int64            `json:"id,omitempty"`
	UUID            string           `json:"uuid,omitempty"`
	MachineID       string           `json:"machine_id,omitempty"`
	CreatedAt       string           `json:"created_at,omitempty"`
	Scenario        *string          `json:"scenario"`
	ScenarioHash    *string          `json:"scenario_hash"`
	ScenarioVersion *string          `json:"scenario_version"`
	Message         *string          `json:"message"`
	EventsCount     *int32           `json:"events_count"`
	StartAt         *string          `json:"start_at"`
	StopAt          *string          `json:"stop_at"`
	Capacity        *int32           `json:"capacity"`
	Leakspeed       *string          `json:"leakspeed"`
	Simulated       *bool            `json:"simulated"`
	Remediation     bool             `json:"remediation,omitempty"`
	Kind            string           `json:"kind,omitempty"`
	Source          *Source          `json:"source"`
	Events          []*Event         `json:"events"`
	Meta            []*Meta          `json:"meta,omitempty"`
	Decisions       []*AlertDecision `json:"decisions,omitempty"`
	Labels          []string         `json:"labels,omitempty"`
}

// Source is the alert source.
type Source struct {
	Scope     *string `json:"scope"`
	Value     *string `json:"value"`
	IP        string  `json:"ip,omitempty"`
	Range     string  `json:"range,omitempty"`
	ASNumber  string  `json:"as_number,omitempty"`
	ASName    string  `json:"as_name,omitempty"`
	Country   string  `json:"cn,omitempty"`
	Latitude  float32 `json:"latitude,omitempty"`
	Longitude float32 `json:"longitude,omitempty"`
}

// Event is one event of an alert.
type Event struct {
	Timestamp *string `json:"timestamp"`
	Meta      []*Meta `json:"meta"`
}

// Meta is a key/value pair. Alert context values are JSON arrays encoded
// as strings.
type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// AlertDecision is a decision attached to an alert.
type AlertDecision struct {
	ID        int64   `json:"id,omitempty"`
	UUID      string  `json:"uuid,omitempty"`
	Duration  *string `json:"duration"`
	Until     string  `json:"until,omitempty"`
	Origin    *string `json:"origin"`
	Scenario  *string `json:"scenario"`
	Scope     *string `json:"scope"`
	Type      *string `json:"type"`
	Value     *string `json:"value"`
	Simulated *bool   `json:"simulated,omitempty"`
}

// ErrNotFound is returned for a missing alert or decision.
var ErrNotFound = errors.New("lapi: not found")

// Watcher is a LAPI client authenticated as a machine (watcher).
type Watcher struct {
	c *Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Watcher returns a watcher client using cfg.Login and cfg.Password.
func (c *Client) Watcher() (*Watcher, error) {
	if c.cfg.Login == "" || c.cfg.Password == "" {
		return nil, errors.New("lapi: watcher login and password are required")
	}
	return &Watcher{c: c}, nil
}

func (w *Watcher) login(ctx context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.token != "" && w.c.now().Before(w.expires.Add(-time.Minute)) {
		return w.token, nil
	}
	body, _ := json.Marshal(map[string]any{"machine_id": w.c.cfg.Login, "password": w.c.cfg.Password, "scenarios": []string{}})
	u := *w.c.base
	u.Path += "/v1/watchers/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := w.c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("lapi login: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("lapi login: %w", err)
	}
	w.token = out.Token
	w.expires, err = time.Parse(time.RFC3339, out.Expire)
	if err != nil {
		w.expires = w.c.now().Add(30 * time.Minute)
	}
	return w.token, nil
}

// do sends an authenticated request and decodes the JSON answer into out.
func (w *Watcher) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, w.c.cfg.Timeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		tok, err := w.login(ctx)
		if err != nil {
			return err
		}
		u := *w.c.base
		u.Path += path
		u.RawQuery = q.Encode()
		var body io.Reader
		if in != nil {
			raw, err := json.Marshal(in)
			if err != nil {
				return err
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("User-Agent", userAgent)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := w.c.client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = resp.Body.Close()
			w.mu.Lock()
			w.token = ""
			w.mu.Unlock()
			continue
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return ErrNotFound
		case resp.StatusCode >= 300:
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("lapi %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		if out == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("lapi %s %s: decode: %w", method, path, err)
		}
		return nil
	}
}

// Alerts lists alerts. Useful parameters: since/until (durations, on
// start_at), limit (0 = all), sort (ASC|DESC by created_at), include_capi,
// has_active_decision, ip, range, scenario, origin.
func (w *Watcher) Alerts(ctx context.Context, q url.Values) ([]*Alert, error) {
	var out []*Alert
	if err := w.do(ctx, http.MethodGet, "/v1/alerts", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Alert returns one alert with its events.
func (w *Watcher) Alert(ctx context.Context, id int64) (*Alert, error) {
	var out Alert
	if err := w.do(ctx, http.MethodGet, "/v1/alerts/"+strconv.FormatInt(id, 10), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PushAlerts creates alerts (a manual decision is an alert carrying it)
// and returns their ids.
func (w *Watcher) PushAlerts(ctx context.Context, alerts []*Alert) ([]string, error) {
	var ids []string
	if err := w.do(ctx, http.MethodPost, "/v1/alerts", nil, alerts, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

type deleted struct {
	NbDeleted string `json:"nbDeleted"`
}

func (d deleted) n() int64 {
	n, _ := strconv.ParseInt(d.NbDeleted, 10, 64)
	return n
}

// DeleteAlert deletes an alert with its decisions. LAPI only accepts this
// from its trusted_ips.
func (w *Watcher) DeleteAlert(ctx context.Context, id int64) error {
	return w.do(ctx, http.MethodDelete, "/v1/alerts/"+strconv.FormatInt(id, 10), nil, nil, nil)
}

// DeleteAlerts deletes the alerts matching q (ip=...) and returns how many.
func (w *Watcher) DeleteAlerts(ctx context.Context, q url.Values) (int64, error) {
	var d deleted
	if err := w.do(ctx, http.MethodDelete, "/v1/alerts", q, nil, &d); err != nil {
		return 0, err
	}
	return d.n(), nil
}

// DeleteDecision deletes one decision.
func (w *Watcher) DeleteDecision(ctx context.Context, id int64) (int64, error) {
	var d deleted
	if err := w.do(ctx, http.MethodDelete, "/v1/decisions/"+strconv.FormatInt(id, 10), nil, nil, &d); err != nil {
		return 0, err
	}
	return d.n(), nil
}

// DeleteDecisions deletes the decisions matching q (ip=..., range=...).
func (w *Watcher) DeleteDecisions(ctx context.Context, q url.Values) (int64, error) {
	var d deleted
	if err := w.do(ctx, http.MethodDelete, "/v1/decisions", q, nil, &d); err != nil {
		return 0, err
	}
	return d.n(), nil
}

// ManualDecision builds the alert that carries a manual decision, the way
// cscli decisions add does.
func ManualDecision(scope, value, typ, duration, scenario, reason, by string, now time.Time) *Alert {
	s := func(v string) *string { return &v }
	zero, f := int32(0), false
	at := now.UTC().Format(time.RFC3339)
	msg := fmt.Sprintf("manual '%s' from '%s'", typ, by)
	if reason != "" {
		msg += ": " + reason
	}
	origin := "cscli"
	src := &Source{Scope: s(scope), Value: s(value)}
	if strings.EqualFold(scope, "ip") {
		src.IP = value
	} else if strings.EqualFold(scope, "range") {
		src.Range = value
	}
	return &Alert{
		Scenario: s(scenario), ScenarioHash: s(""), ScenarioVersion: s(""), Message: s(msg), EventsCount: &zero,
		StartAt: s(at), StopAt: s(at), Capacity: &zero, Leakspeed: s("0"), Simulated: &f, Source: src, Events: []*Event{},
		Decisions: []*AlertDecision{{Duration: s(duration), Origin: &origin, Scenario: s(scenario), Scope: s(scope), Type: s(typ), Value: s(value)}},
	}
}
