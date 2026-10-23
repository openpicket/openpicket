package crowdsecsync

import (
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

// MaxBundle bounds a bundle (decompressed).
const MaxBundle = 256 << 20

// Handler serves the sync protocol, authenticated by a shared header (the
// datasource token: only the manager may push records or content).
func Handler(s *Syncer, header, token string) http.Handler {
	auth := func(r *http.Request) bool {
		got := r.Header.Get(header)
		return token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	}
	writeStatus := func(w http.ResponseWriter, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(s.Status())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.cfg.Engine.Running() {
			http.Error(w, "waiting for content", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET "+hubitem.PathStatus, func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeStatus(w, http.StatusOK)
	})
	mux.HandleFunc("PUT "+hubitem.PathBundle, func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			defer zr.Close()
			body = zr
		}
		var b hubitem.Bundle
		if err := json.NewDecoder(io.LimitReader(body, MaxBundle)).Decode(&b); err != nil {
			http.Error(w, "bad bundle: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch err := s.Apply(r.Context(), &b); {
		case errors.Is(err, ErrRefused):
			writeStatus(w, http.StatusUnprocessableEntity)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			writeStatus(w, http.StatusOK)
		}
	})
	return mux
}
