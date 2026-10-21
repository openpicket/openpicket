package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/auth"
)

// Without suricontroller, /suricata/ explains what to configure instead of
// falling through to the web UI (which redirects to its home page).
func TestSuricataNotConfigured(t *testing.T) {
	srv, err := New(Config{DB: &pgxpool.Pool{}, Auth: &auth.Chain{}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.Mount(mux)
	mux.Handle("/", http.NotFoundHandler()) // the web UI
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/suricata/", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "OPENPICKET_SURICONTROLLER_URL") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
