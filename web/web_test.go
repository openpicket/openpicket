package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler()
	for _, p := range []string{"/", "/alerts", "/nodes/edge-01"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		// Without a build the handler explains how to build; with one it
		// answers index.html for every route.
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		if rec.Code == http.StatusOK && rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: no CSP", p)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("POST served")
	}
}
