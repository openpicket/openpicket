// Package api is the management API of openpicket-manager (Connect, under
// /api/) and the authenticated proxy to openpicket-suricontroller
// (/suricata/), docs/ARCHITECTURE.md §5.7.
//
// Every procedure has an entry in the procedures table: the least role it
// requires, whether it changes state (refused in read-only mode) and
// whether it is audited. A procedure without an entry is refused.
package api

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/gen/openpicket/api/v1/apiv1connect"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/manager/policy"
	"github.com/openpicket/openpicket/manager/settings"
)

// Config holds the dependencies of the API.
type Config struct {
	DB   *pgxpool.Pool
	Auth *auth.Chain
	// ReadOnly refuses every procedure that changes state.
	ReadOnly bool
	// AllowedOrigins may send state-changing requests besides the
	// request's own origin (scheme://host[:port]).
	AllowedOrigins []string
	// TrustProxyHeaders uses CF-Connecting-IP / X-Forwarded-For as the
	// client address (login rate limit, audit).
	TrustProxyHeaders bool
	Geo               *geo.Store
	Policies          *policy.Service
	Settings          *settings.Store
	// HostKey is the manager public key line agents pin.
	HostKey string
	Replica string
	Version string
	// Suricontroller is the openpicket-suricontroller base URL proxied at
	// /suricata/; nil disables the proxy.
	Suricontroller *url.URL
	// PrincipalKey signs the principal tokens of proxied requests.
	PrincipalKey ed25519.PrivateKey
	// Status reports the health of the manager's components.
	Status func(ctx context.Context) []*apiv1.ComponentStatus
	Logger *slog.Logger
	Now    func() time.Time
}

// Server serves the API.
type Server struct {
	cfg   Config
	log   *slog.Logger
	login *limiter
}

// New creates a server.
func New(cfg Config) (*Server, error) {
	if cfg.DB == nil || cfg.Auth == nil {
		return nil, errors.New("api: DB and Auth are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Suricontroller != nil && len(cfg.PrincipalKey) != ed25519.PrivateKeySize {
		return nil, errors.New("api: the suricontroller proxy needs a principal key")
	}
	return &Server{cfg: cfg, log: cfg.Logger.With("component", "api"), login: newLimiter(5, time.Minute)}, nil
}

// spec describes the access rules of a procedure.
type spec struct {
	// role is the least role required; "" is public.
	role string
	// write procedures are refused in read-only mode.
	write bool
	audit bool
}

var (
	public = spec{}
	read   = spec{role: auth.RoleViewer}
	// own: changes only the caller's own preferences.
	own = spec{role: auth.RoleViewer}
	op  = spec{role: auth.RoleOperator, write: true, audit: true}
	adm = spec{role: auth.RoleAdmin, write: true, audit: true}
)

// procedures lists every procedure (and HTTP endpoint) served.
var procedures = map[string]spec{
	apiv1connect.AuthServiceGetAuthInfoProcedure: public,
	apiv1connect.AuthServiceLoginProcedure:       public,
	apiv1connect.AuthServiceLogoutProcedure:      public,

	apiv1connect.NodeServiceListNodesProcedure:         read,
	apiv1connect.NodeServiceGetNodeProcedure:           read,
	apiv1connect.NodeServiceGetConnectionInfoProcedure: read,
	apiv1connect.NodeServiceRegisterNodeProcedure:      op,
	apiv1connect.NodeServiceUpdateNodeProcedure:        op,
	apiv1connect.NodeServiceDeleteNodeProcedure:        op,

	apiv1connect.AlertServiceSearchAlertsProcedure: read,
	apiv1connect.AlertServiceGetAlertProcedure:     read,
	apiv1connect.AlertServiceFacetsProcedure:       read,
	apiv1connect.AlertServiceDeleteAlertsProcedure: op,

	apiv1connect.DecisionServiceSearchDecisionsProcedure: read,
	apiv1connect.DecisionServiceGetPropagationProcedure:  read,
	apiv1connect.DecisionServiceAddDecisionProcedure:     op,
	apiv1connect.DecisionServiceDeleteDecisionsProcedure: op,
	apiv1connect.DecisionServiceCleanupIPProcedure:       op,

	apiv1connect.DashboardServiceGetSummaryProcedure: read,

	apiv1connect.PolicyServiceListPoliciesProcedure:      read,
	apiv1connect.PolicyServiceListAddressListsProcedure:  read,
	apiv1connect.PolicyServicePolicyHistoryProcedure:     read,
	apiv1connect.PolicyServicePreviewBundleProcedure:     read,
	apiv1connect.PolicyServicePutPolicyProcedure:         op,
	apiv1connect.PolicyServiceDeletePolicyProcedure:      op,
	apiv1connect.PolicyServiceReorderPoliciesProcedure:   op,
	apiv1connect.PolicyServicePutAddressListProcedure:    op,
	apiv1connect.PolicyServiceDeleteAddressListProcedure: op,

	apiv1connect.GeoServiceListDatabasesProcedure:  read,
	apiv1connect.GeoServiceLookupProcedure:         read,
	apiv1connect.GeoServiceDeleteDatabaseProcedure: adm,
	geoUploadPath: adm,

	apiv1connect.SystemServiceGetLogPolicyProcedure:      read,
	apiv1connect.SystemServiceGetStatusProcedure:         read,
	apiv1connect.SystemServiceListSavedFiltersProcedure:  read,
	apiv1connect.SystemServiceSaveFilterProcedure:        own,
	apiv1connect.SystemServiceDeleteSavedFilterProcedure: own,
	apiv1connect.SystemServiceListAuditProcedure:         {role: auth.RoleOperator},
	apiv1connect.SystemServiceSetLogPolicyProcedure:      adm,
}

const geoUploadPath = "/geo/upload"

// Handler serves the API (mount at /api/ with the prefix stripped).
func (s *Server) Handler() http.Handler {
	opts := []connect.HandlerOption{connect.WithInterceptors(connect.UnaryInterceptorFunc(s.auditInterceptor)), connect.WithReadMaxBytes(1 << 20)}
	mux := http.NewServeMux()
	mux.Handle(apiv1connect.NewAuthServiceHandler(&authService{s}, append(opts, connect.WithReadMaxBytes(16<<10))...))
	mux.Handle(apiv1connect.NewNodeServiceHandler(&nodeService{s}, opts...))
	mux.Handle(apiv1connect.NewPolicyServiceHandler(&policyService{s}, opts...))
	mux.Handle(apiv1connect.NewGeoServiceHandler(&geoService{s}, opts...))
	mux.Handle(apiv1connect.NewSystemServiceHandler(&systemService{s}, opts...))
	mux.Handle(apiv1connect.NewAlertServiceHandler(apiv1connect.UnimplementedAlertServiceHandler{}, opts...))
	mux.Handle(apiv1connect.NewDecisionServiceHandler(apiv1connect.UnimplementedDecisionServiceHandler{}, opts...))
	mux.Handle(apiv1connect.NewDashboardServiceHandler(apiv1connect.UnimplementedDashboardServiceHandler{}, opts...))
	mux.HandleFunc("POST "+geoUploadPath, s.uploadGeo)
	return s.middleware(mux)
}

var errorWriter = connect.NewErrorWriter()

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err *connect.Error) {
	if errorWriter.IsSupported(r) {
		_ = errorWriter.Write(w, r, err)
		return
	}
	code := http.StatusForbidden
	switch err.Code() {
	case connect.CodeUnauthenticated:
		code = http.StatusUnauthorized
	case connect.CodeNotFound:
		code = http.StatusNotFound
	case connect.CodeInvalidArgument:
		code = http.StatusBadRequest
	case connect.CodeResourceExhausted:
		code = http.StatusTooManyRequests
	}
	http.Error(w, err.Message(), code)
}

type remoteAddrKey struct{}

// clientAddr returns the client address.
func (s *Server) clientAddr(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if v := r.Header.Get("Cf-Connecting-Ip"); v != "" {
			return v
		}
		// The rightmost entry was added by the trusted proxy.
		if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
			parts := strings.Split(v[len(v)-1], ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func remoteAddr(ctx context.Context) string {
	a, _ := ctx.Value(remoteAddrKey{}).(string)
	return a
}

// middleware authenticates, checks the origin of state-changing requests
// and enforces the procedures table.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sp, ok := procedures[r.URL.Path]
		if !ok {
			s.writeError(w, r, connect.NewError(connect.CodeNotFound, errors.New("unknown procedure")))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := s.checkOrigin(r); err != nil {
				s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, err))
				return
			}
		}
		ctx := context.WithValue(r.Context(), remoteAddrKey{}, s.clientAddr(r))
		p, prov, err := s.cfg.Auth.Authenticate(r)
		switch {
		case err == nil:
			ctx = auth.WithPrincipal(ctx, p)
			ctx = context.WithValue(ctx, providerKey{}, prov)
		case sp.role == "":
			// Public procedures run anonymously.
		case errors.Is(err, auth.ErrForbidden):
			s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("no OpenPicket role is assigned to this user")))
			return
		default:
			s.writeError(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required")))
			return
		}
		if sp.role != "" && !p.Has(sp.role) {
			s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("this requires the "+sp.role+" role")))
			return
		}
		if sp.write && s.cfg.ReadOnly {
			s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("OpenPicket is in read-only mode")))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type providerKey struct{}

// checkOrigin protects cookie sessions against CSRF: browsers send Origin
// (or Sec-Fetch-Site) with every cross-site POST, and cannot send the
// Connect headers or a JSON body cross-site without a CORS preflight,
// which this server never answers.
func (s *Server) checkOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		if o := r.Header.Get("Origin"); o == "" || !s.originAllowed(r, o) {
			return errors.New("cross-site request refused")
		}
	}
	if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(r, o) {
		return errors.New("origin " + o + " is not allowed")
	}
	if r.URL.Path == geoUploadPath {
		// multipart/form-data is a "simple" content type: require a custom
		// header (preflighted).
		if r.Header.Get("X-OpenPicket-Request") == "" {
			return errors.New("missing X-OpenPicket-Request header")
		}
		return nil
	}
	if !isConnectRequest(r) {
		return errors.New("missing Connect protocol headers")
	}
	return nil
}

func (s *Server) originAllowed(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if s.cfg.TrustProxyHeaders {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" && strings.EqualFold(u.Host, h) {
			return true
		}
	}
	for _, a := range s.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimSuffix(a, "/"), origin) {
			return true
		}
	}
	return false
}

func isConnectRequest(r *http.Request) bool {
	if r.Header.Get("Connect-Protocol-Version") != "" {
		return true
	}
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+") || ct == "application/proto"
}

// by returns the audit name of the caller.
func by(ctx context.Context) string {
	if p := auth.FromContext(ctx); p != nil {
		return p.ID()
	}
	return "anonymous"
}

// toConnectError maps service errors to Connect codes.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var ce *connect.Error
	switch {
	case errors.As(err, &ce):
		return err
	case errors.Is(err, policy.ErrNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, errNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, policy.ErrInvalid), errors.Is(err, errInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, errExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeCanceled, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

var (
	errNotFound = errors.New("not found")
	errInvalid  = errors.New("invalid argument")
	errExists   = errors.New("already exists")
)
