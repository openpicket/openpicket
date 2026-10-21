// Package misptest is a fake MISP REST API for tests: attribute search by
// tag, tags, attribute edits, events and attribute creation.
package misptest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpicket/openpicket/manager/misp"
)

// MISP is a fake MISP.
type MISP struct {
	*httptest.Server
	Key string

	mu     sync.Mutex
	attrs  []*misp.Attribute
	events []misp.Event
	nextID int
	// Down makes every call fail with 503.
	Down bool
}

// New starts a fake MISP.
func New() *MISP {
	m := &MISP{Key: "test-key", nextID: 1}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	return m
}

func (m *MISP) id() string {
	m.nextID++
	return strconv.Itoa(m.nextID)
}

// Add stores an attribute as an analyst would in the MISP UI.
func (m *MISP) Add(typ, value string, toIDS bool, tags ...string) *misp.Attribute {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := &misp.Attribute{ID: m.id(), EventID: "1", UUID: "uuid-" + m.id(), Type: typ, Value: value, ToIDS: toIDS,
		Timestamp: strconv.FormatInt(time.Now().Unix(), 10)}
	for _, t := range tags {
		a.Tags = append(a.Tags, misp.Tag{ID: m.id(), Name: t})
	}
	m.attrs = append(m.attrs, a)
	return a
}

// Attributes returns a copy of the attributes.
func (m *MISP) Attributes() []misp.Attribute {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]misp.Attribute, 0, len(m.attrs))
	for _, a := range m.attrs {
		c := *a
		c.Tags = slices.Clone(a.Tags)
		out = append(out, c)
	}
	return out
}

// Delete soft-deletes an attribute.
func (m *MISP) Delete(uuid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.attrs {
		if a.UUID == uuid {
			a.Deleted = true
		}
	}
}

func (m *MISP) find(uuid string) *misp.Attribute {
	for _, a := range m.attrs {
		if a.UUID == uuid || a.ID == uuid {
			return a
		}
	}
	return nil
}

func (m *MISP) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != m.Key {
		http.Error(w, `{"message":"Authentication failed."}`, http.StatusForbidden)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	str := func(k string) string { s, _ := in[k].(string); return s }
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.URL.Path == "/attributes/restSearch":
		var prefixes []string
		if tags, ok := in["tags"].([]any); ok {
			for _, t := range tags {
				prefixes = append(prefixes, strings.TrimSuffix(t.(string), "%"))
			}
		}
		var out []misp.Attribute
		for _, a := range m.attrs {
			match := len(prefixes) == 0
			for _, t := range a.Tags {
				for _, p := range prefixes {
					if strings.HasPrefix(t.Name, p) {
						match = true
					}
				}
			}
			if !match {
				continue
			}
			c := *a
			for _, e := range m.events {
				if e.ID == a.EventID {
					c.Event = &struct {
						ID   string `json:"id"`
						Info string `json:"info"`
					}{e.ID, e.Info}
				}
			}
			out = append(out, c)
		}
		reply(map[string]any{"response": map[string]any{"Attribute": out}})
	case r.URL.Path == "/tags/attachTagToObject":
		a := m.find(str("uuid"))
		if a == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !slices.ContainsFunc(a.Tags, func(t misp.Tag) bool { return t.Name == str("tag") }) {
			a.Tags = append(a.Tags, misp.Tag{ID: m.id(), Name: str("tag")})
		}
		reply(map[string]any{"saved": true})
	case r.URL.Path == "/tags/removeTagFromObject":
		a := m.find(str("uuid"))
		if a == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		a.Tags = slices.DeleteFunc(a.Tags, func(t misp.Tag) bool { return t.Name == str("tag") })
		reply(map[string]any{"saved": true})
	case strings.HasPrefix(r.URL.Path, "/attributes/edit/"):
		a := m.find(strings.TrimPrefix(r.URL.Path, "/attributes/edit/"))
		if a == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if v, ok := in["to_ids"].(bool); ok {
			a.ToIDS = v
		}
		reply(map[string]any{"Attribute": a})
	case r.URL.Path == "/events/restSearch":
		var out []map[string]any
		for _, e := range m.events {
			if strings.Contains(e.Info, str("eventinfo")) {
				out = append(out, map[string]any{"Event": e})
			}
		}
		reply(map[string]any{"response": out})
	case r.URL.Path == "/events/add":
		ev, _ := in["Event"].(map[string]any)
		info, _ := ev["info"].(string)
		e := misp.Event{ID: m.id(), UUID: "event-" + m.id(), Info: info}
		m.events = append(m.events, e)
		reply(map[string]any{"Event": e})
	case strings.HasPrefix(r.URL.Path, "/attributes/add/"):
		a := &misp.Attribute{ID: m.id(), EventID: strings.TrimPrefix(r.URL.Path, "/attributes/add/"), UUID: "uuid-" + m.id(),
			Type: str("type"), Value: str("value"), Comment: str("comment"), Timestamp: strconv.FormatInt(time.Now().Unix(), 10)}
		a.ToIDS, _ = in["to_ids"].(bool)
		m.attrs = append(m.attrs, a)
		reply(map[string]any{"Attribute": a})
	default:
		http.Error(w, "not implemented", http.StatusNotFound)
	}
}
