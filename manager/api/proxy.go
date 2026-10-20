package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/pkg/principal"
)

// SuricataPrefix is where openpicket-suricontroller is served.
const SuricataPrefix = "/suricata"

// Mount adds the API (/api/) and the suricontroller proxy (/suricata/) to
// mux. Without suricontroller, /suricata/ explains what to configure (the
// web UI would otherwise answer and redirect to its home page).
func (s *Server) Mount(mux *http.ServeMux) {
	mux.Handle("/api/", http.StripPrefix("/api", s.Handler()))
	if s.cfg.Suricontroller != nil {
		mux.Handle(SuricataPrefix+"/", s.suricataProxy())
		return
	}
	mux.HandleFunc(SuricataPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Suricata management is not configured: set OPENPICKET_SURICONTROLLER_URL on openpicket-manager "+
			"(the Helm chart does it when suricontroller.enabled is true).", http.StatusServiceUnavailable)
	})
}

// suricataProxy forwards authenticated requests to openpicket-suricontroller
// with a principal token minted for each request. The browser's cookies and
// any principal header it sent are dropped.
func (s *Server) suricataProxy() http.Handler {
	target := s.cfg.Suricontroller
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = joinPath(target.Path, strings.TrimPrefix(pr.In.URL.Path, SuricataPrefix))
			pr.Out.URL.RawPath = ""
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(principal.Header)
			pr.SetXForwarded()
			if tok, ok := pr.In.Context().Value(tokenKey{}).(string); ok {
				pr.Out.Header.Set(principal.Header, tok)
			}
		},
		// Log tails stream.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("suricontroller proxy", "path", r.URL.Path, "err", err)
			http.Error(w, "openpicket-suricontroller is unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _, err := s.cfg.Auth.Authenticate(r)
		if err != nil {
			if errors.Is(err, auth.ErrForbidden) {
				http.Error(w, "no OpenPicket role is assigned to this user", http.StatusForbidden)
				return
			}
			if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			s.writeError(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required")))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); (o != "" && !s.originAllowed(r, o)) || (o == "" && r.Header.Get("Sec-Fetch-Site") == "cross-site") {
				s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("cross-site request refused")))
				return
			}
		}
		roles := []string{p.Role()}
		if s.cfg.ReadOnly {
			roles = []string{principal.RoleViewer}
		}
		tok, err := principal.Mint(s.cfg.PrincipalKey, principal.AudienceSuricontroller, p.ID(), p.Display(), roles, principal.DefaultTTL, s.cfg.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx := r.Context()
		ctx = contextWithToken(ctx, tok)
		rp.ServeHTTP(w, r.WithContext(ctx))
	})
}

func joinPath(base, p string) string {
	if p == "" {
		p = "/"
	}
	return strings.TrimSuffix(base, "/") + p
}

type tokenKey struct{}

func contextWithToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, tokenKey{}, tok)
}
