// Package kubetest is a fake Kubernetes API for the collector's tests:
// pods (label, field and workload selection) and followed container logs.
package kubetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Pod is a fake pod; its containers run.
type Pod struct {
	Namespace, Name, UID string
	Labels               map[string]string
	ServiceAccount       string
	Containers           []string
}

// API serves the fake.
type API struct {
	*httptest.Server

	mu        sync.Mutex
	pods      []Pod
	workloads map[string]any // "ns/kind/name" -> spec.selector
	logs      map[string]*log
	requests  []url.Values
}

type log struct {
	lines   []string
	changed chan struct{} // closed on a change
	end     int           // streams opened before an end request stop
}

// New starts a fake API.
func New(t testing.TB) *API {
	a := &API{workloads: map[string]any{}, logs: map[string]*log{}}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Close)
	return a
}

// AddPod adds (or replaces) a pod.
func (a *API) AddPod(p Pod) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeLocked(p.Namespace, p.Name)
	a.pods = append(a.pods, p)
}

// RemovePod deletes a pod; its log streams end.
func (a *API) RemovePod(namespace, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeLocked(namespace, name)
	for k, l := range a.logs {
		if strings.HasPrefix(k, namespace+"/"+name+"/") {
			l.end++
			a.notify(l)
		}
	}
}

func (a *API) removeLocked(namespace, name string) {
	out := a.pods[:0]
	for _, p := range a.pods {
		if p.Namespace != namespace || p.Name != name {
			out = append(out, p)
		}
	}
	a.pods = out
}

// SetWorkload gives a workload ("deployment") its selector
// (metav1.LabelSelector as JSON-able value).
func (a *API) SetWorkload(namespace, kind, name string, selector any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.workloads[namespace+"/"+kind+"/"+name] = selector
}

func (a *API) logOf(key string) *log {
	l := a.logs[key]
	if l == nil {
		l = &log{changed: make(chan struct{})}
		a.logs[key] = l
	}
	return l
}

func (a *API) notify(l *log) {
	close(l.changed)
	l.changed = make(chan struct{})
}

// Log appends a line written at ts to a container's log.
func (a *API) Log(namespace, pod, container string, ts time.Time, msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.logOf(namespace + "/" + pod + "/" + container)
	l.lines = append(l.lines, ts.UTC().Format(time.RFC3339Nano)+" "+msg)
	a.notify(l)
}

// EndStreams ends the open log streams of a container (kubelet log
// rotation, container restart).
func (a *API) EndStreams(namespace, pod, container string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.logOf(namespace + "/" + pod + "/" + container)
	l.end++
	a.notify(l)
}

// LogRequests returns the query of every log request so far.
func (a *API) LogRequests() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.requests...)
}

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	// /api/v1/namespaces/{ns}/pods
	case len(parts) == 5 && parts[0] == "api" && parts[4] == "pods":
		a.listPods(w, parts[3], r.URL.Query())
	// /api/v1/namespaces/{ns}/pods/{pod}/log
	case len(parts) == 7 && parts[0] == "api" && parts[6] == "log":
		a.streamLog(w, r, parts[3], parts[5])
	// /apis/apps/v1/namespaces/{ns}/{resource}/{name}
	case len(parts) == 7 && parts[0] == "apis":
		a.mu.Lock()
		sel, ok := a.workloads[parts[4]+"/"+strings.TrimSuffix(parts[5], "s")+"/"+parts[6]]
		a.mu.Unlock()
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"spec": map[string]any{"selector": sel}})
	default:
		http.NotFound(w, r)
	}
}

// matchLabels supports "k=v" and "k in (a,b)" terms.
func matchLabels(sel string, labels map[string]string) bool {
	if sel == "" {
		return true
	}
	for _, term := range splitTerms(sel) {
		if k, vs, ok := strings.Cut(term, " in ("); ok {
			found := false
			for _, v := range strings.Split(strings.TrimSuffix(vs, ")"), ",") {
				found = found || labels[k] == v
			}
			if !found {
				return false
			}
			continue
		}
		k, v, _ := strings.Cut(term, "=")
		if labels[k] != v {
			return false
		}
	}
	return true
}

// splitTerms splits on commas outside parentheses.
func splitTerms(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func (a *API) listPods(w http.ResponseWriter, ns string, q url.Values) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var items []map[string]any
	for _, p := range a.pods {
		if p.Namespace != ns || !matchLabels(q.Get("labelSelector"), p.Labels) || !matchFields(q.Get("fieldSelector"), p) {
			continue
		}
		var containers, statuses []map[string]any
		for _, c := range p.Containers {
			containers = append(containers, map[string]any{"name": c})
			statuses = append(statuses, map[string]any{"name": c, "state": map[string]any{"running": map[string]any{"startedAt": "2026-10-26T00:00:00Z"}}})
		}
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": p.Name, "namespace": p.Namespace, "uid": p.UID, "labels": p.Labels},
			"spec":     map[string]any{"containers": containers, "serviceAccountName": p.ServiceAccount},
			"status":   map[string]any{"phase": "Running", "containerStatuses": statuses},
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

func matchFields(sel string, p Pod) bool {
	for _, term := range strings.Split(sel, ",") {
		k, v, _ := strings.Cut(term, "=")
		switch k {
		case "", "status.phase":
		case "spec.serviceAccountName":
			if p.ServiceAccount != v {
				return false
			}
		case "metadata.name":
			if p.Name != v {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (a *API) streamLog(w http.ResponseWriter, r *http.Request, ns, pod string) {
	q := r.URL.Query()
	key := ns + "/" + pod + "/" + q.Get("container")
	a.mu.Lock()
	a.requests = append(a.requests, q)
	l := a.logOf(key)
	end := l.end
	start := 0
	switch {
	case q.Get("sinceTime") != "":
		since, err := time.Parse(time.RFC3339, q.Get("sinceTime"))
		if err != nil {
			a.mu.Unlock()
			http.Error(w, "bad sinceTime", http.StatusBadRequest)
			return
		}
		start = len(l.lines)
		for i, line := range l.lines {
			ts, _, _ := strings.Cut(line, " ")
			if t, _ := time.Parse(time.RFC3339Nano, ts); !t.Before(since) {
				start = i
				break
			}
		}
	case q.Get("tailLines") != "":
		var n int
		_, _ = fmt.Sscan(q.Get("tailLines"), &n)
		start = max(len(l.lines)-n, 0)
	}
	a.mu.Unlock()
	fl, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}
	for {
		a.mu.Lock()
		lines := append([]string(nil), l.lines[start:]...)
		start = len(l.lines)
		changed, ended := l.changed, l.end != end
		a.mu.Unlock()
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
		if fl != nil {
			fl.Flush()
		}
		if ended {
			return
		}
		select {
		case <-changed:
		case <-r.Context().Done():
			return
		}
	}
}
