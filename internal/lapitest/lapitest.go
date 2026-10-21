// Package lapitest is a fake CrowdSec LAPI watcher API for tests: login,
// alert listing (sort, limit, has_active_decision), alert creation and
// the delete endpoints.
package lapitest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpicket/openpicket/manager/lapi"
)

// LAPI is a fake LAPI.
type LAPI struct {
	*httptest.Server
	Login, Password string

	mu      sync.Mutex
	alerts  []*lapi.Alert
	nextID  int64
	nextDec int64
	Now     func() time.Time
	// Requests counts calls per "METHOD path".
	Requests map[string]int
}

// New starts a fake LAPI.
func New() *LAPI {
	l := &LAPI{Login: "openpicket", Password: "pw", nextID: 1, nextDec: 1, Now: time.Now, Requests: map[string]int{}}
	l.Server = httptest.NewServer(http.HandlerFunc(l.serve))
	return l
}

func s(v string) *string { return &v }

// Add stores an alert as an agent would and returns it. decision is the
// remaining duration of a ban on the source ("" for none).
func (l *LAPI) Add(scenario, ip, country, node string, decision time.Duration, created time.Time) *lapi.Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := int32(5)
	f := false
	a := &lapi.Alert{ID: l.nextID, UUID: "u" + strconv.FormatInt(l.nextID, 10), MachineID: "agent-1", CreatedAt: created.UTC().Format(time.RFC3339),
		Scenario: s(scenario), Message: s("Ip " + ip + " performed '" + scenario + "'"), EventsCount: &ev, StartAt: s(created.Add(-time.Minute).UTC().Format(time.RFC3339)),
		StopAt: s(created.UTC().Format(time.RFC3339)), Simulated: &f, Remediation: decision > 0,
		Source: &lapi.Source{Scope: s("Ip"), Value: s(ip), IP: ip, Country: country, ASName: "TEST-AS", ASNumber: "64500"},
		Meta:   []*lapi.Meta{{Key: "node_id", Value: `["` + node + `"]`}, {Key: "dst_ip", Value: `["192.168.1.10"]`}, {Key: "direction", Value: `["inbound"]`}},
		Events: []*lapi.Event{{Timestamp: s(created.UTC().Format(time.RFC3339)), Meta: []*lapi.Meta{{Key: "dest_port", Value: "443"}}}},
	}
	l.nextID++
	if decision > 0 {
		l.addDecision(a, "ban", "Ip", ip, "crowdsec", scenario, created.Add(decision))
	}
	l.alerts = append(l.alerts, a)
	return a
}

func (l *LAPI) addDecision(a *lapi.Alert, typ, scope, value, origin, scenario string, until time.Time) {
	f := false
	a.Decisions = append(a.Decisions, &lapi.AlertDecision{ID: l.nextDec, Duration: s(time.Until(until).String()), Until: until.UTC().Format(time.RFC3339),
		Origin: s(origin), Scenario: s(scenario), Scope: s(scope), Type: s(typ), Value: s(value), Simulated: &f})
	l.nextDec++
}

// Alerts returns a copy of the stored alerts.
func (l *LAPI) Alerts() []*lapi.Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.alerts)
}

func (l *LAPI) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.Requests[r.Method+" "+r.URL.Path]++
	l.mu.Unlock()
	if r.URL.Path == "/v1/watchers/login" {
		var in struct {
			MachineID string `json:"machine_id"`
			Password  string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.MachineID != l.Login || in.Password != l.Password {
			http.Error(w, `{"message":"bad credentials"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "200", "token": "tok", "expire": l.Now().Add(time.Hour).Format(time.RFC3339)})
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/alerts":
		out := slices.Clone(l.alerts)
		if q.Get("has_active_decision") == "true" {
			out = slices.DeleteFunc(out, func(a *lapi.Alert) bool {
				return !slices.ContainsFunc(a.Decisions, func(d *lapi.AlertDecision) bool {
					t, _ := time.Parse(time.RFC3339, d.Until)
					return t.After(now)
				})
			})
		}
		if sc := q.Get("scenario"); sc != "" {
			// LAPI matches the alert's scenario or one of its decisions'.
			out = slices.DeleteFunc(out, func(a *lapi.Alert) bool {
				if a.Scenario != nil && *a.Scenario == sc {
					return false
				}
				return !slices.ContainsFunc(a.Decisions, func(d *lapi.AlertDecision) bool { return d.Scenario != nil && *d.Scenario == sc })
			})
		}
		if q.Get("sort") != "ASC" {
			slices.Reverse(out)
		}
		limit := 100
		if v := q.Get("limit"); v != "" {
			limit, _ = strconv.Atoi(v)
		}
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		if out == nil {
			out = []*lapi.Alert{}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/alerts/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/alerts/"), 10, 64)
		for _, a := range l.alerts {
			if a.ID == id {
				_ = json.NewEncoder(w).Encode(a)
				return
			}
		}
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/alerts":
		var in []*lapi.Alert
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var ids []string
		for _, a := range in {
			a.ID = l.nextID
			l.nextID++
			a.CreatedAt = now.UTC().Format(time.RFC3339)
			a.MachineID = l.Login
			decs := a.Decisions
			a.Decisions = nil
			for _, d := range decs {
				dur, err := time.ParseDuration(*d.Duration)
				if err != nil {
					http.Error(w, "bad duration "+*d.Duration, http.StatusBadRequest)
					return
				}
				l.addDecision(a, *d.Type, *d.Scope, *d.Value, *d.Origin, *d.Scenario, now.Add(dur))
			}
			l.alerts = append(l.alerts, a)
			ids = append(ids, strconv.FormatInt(a.ID, 10))
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ids)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/alerts/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/alerts/"), 10, 64)
		n := len(l.alerts)
		l.alerts = slices.DeleteFunc(l.alerts, func(a *lapi.Alert) bool { return a.ID == id })
		if n == len(l.alerts) {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "1 deleted"})
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/alerts":
		ip := q.Get("ip")
		n := len(l.alerts)
		l.alerts = slices.DeleteFunc(l.alerts, func(a *lapi.Alert) bool { return a.Source != nil && *a.Source.Value == ip })
		_ = json.NewEncoder(w).Encode(map[string]string{"nbDeleted": strconv.Itoa(n - len(l.alerts))})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/decisions"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/v1/decisions/"), 10, 64)
		ip := q.Get("ip")
		n := 0
		// Like LAPI, a deleted decision stays on its alert as expired.
		for _, a := range l.alerts {
			for _, d := range a.Decisions {
				until, _ := time.Parse(time.RFC3339, d.Until)
				if (d.ID == id || (ip != "" && *d.Value == ip)) && until.After(now) {
					d.Until = now.UTC().Format(time.RFC3339)
					d.Duration = s("0s")
					n++
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"nbDeleted": strconv.Itoa(n)})
	default:
		http.Error(w, "not implemented", http.StatusNotFound)
	}
}
