package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/auth"
)

type authService struct{ s *Server }

func toPrincipal(p *auth.Principal) *apiv1.Principal {
	if p == nil {
		return nil
	}
	return &apiv1.Principal{Id: p.ID(), Name: p.Display(), Email: p.Email, Role: p.Role(), Groups: p.Groups, Provider: p.Provider}
}

func (a *authService) GetAuthInfo(ctx context.Context, _ *connect.Request[apiv1.GetAuthInfoRequest]) (*connect.Response[apiv1.GetAuthInfoResponse], error) {
	res := &apiv1.GetAuthInfoResponse{Principal: toPrincipal(auth.FromContext(ctx)), ReadOnly: a.s.cfg.ReadOnly, Version: a.s.cfg.Version}
	_, res.PasswordLogin = auth.Find[auth.PasswordLogin](a.s.cfg.Auth)
	for _, p := range a.s.cfg.Auth.Providers {
		if ext, ok := p.(auth.ExternalLogin); ok && ext.LoginURL("/") != "" {
			res.LoginUrl = ext.LoginURL("/")
			break
		}
	}
	if prov, _ := ctx.Value(providerKey{}).(auth.Provider); prov != nil {
		if ext, ok := prov.(auth.ExternalLogin); ok {
			res.LogoutUrl = ext.LogoutURL()
		}
	}
	if res.Principal != nil {
		f := &apiv1.Features{Logs: a.s.cfg.Logs != nil, Metrics: a.s.cfg.Metrics != nil && a.s.cfg.Metrics.Configured(), Suricata: a.s.cfg.Suricontroller != nil}
		for _, l := range a.s.cfg.LAPIs {
			f.LapiInstances = append(f.LapiInstances, l.Name)
		}
		res.Features = f
	}
	return connect.NewResponse(res), nil
}

func (a *authService) Login(ctx context.Context, req *connect.Request[apiv1.LoginRequest]) (*connect.Response[apiv1.LoginResponse], error) {
	var (
		login  auth.PasswordLogin
		issuer auth.SessionIssuer
		name   string
	)
	for _, p := range a.s.cfg.Auth.Providers {
		pl, ok1 := p.(auth.PasswordLogin)
		si, ok2 := p.(auth.SessionIssuer)
		if ok1 && ok2 {
			login, issuer, name = pl, si, p.Name()
			break
		}
	}
	if login == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("password login is disabled"))
	}
	if !a.s.login.allow(remoteAddr(ctx), a.s.cfg.Now()) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many login attempts, try again later"))
	}
	p, err := login.Login(ctx, req.Msg.GetUsername(), req.Msg.GetPassword())
	if err != nil {
		a.s.audit(ctx, "AuthService.LoginFailed", req.Msg.GetUsername(), "")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid username or password"))
	}
	p.Provider = name
	if len(p.Roles) == 0 && a.s.cfg.Auth.Roles != nil {
		p.Roles = a.s.cfg.Auth.Roles.Map(p)
	}
	res := connect.NewResponse(&apiv1.LoginResponse{Principal: toPrincipal(p)})
	if err := issuer.IssueSession(headerWriter(res.Header()), p); err != nil {
		return nil, toConnectError(err)
	}
	a.s.audit(auth.WithPrincipal(ctx, p), "AuthService.Login", p.ID(), "")
	return res, nil
}

func (a *authService) Logout(ctx context.Context, _ *connect.Request[apiv1.LogoutRequest]) (*connect.Response[apiv1.LogoutResponse], error) {
	res := connect.NewResponse(&apiv1.LogoutResponse{})
	for _, p := range a.s.cfg.Auth.Providers {
		if si, ok := p.(auth.SessionIssuer); ok {
			si.ClearSession(headerWriter(res.Header()))
		}
	}
	if prov, _ := ctx.Value(providerKey{}).(auth.Provider); prov != nil {
		if ext, ok := prov.(auth.ExternalLogin); ok {
			res.Msg.RedirectUrl = ext.LogoutURL()
		}
	}
	return res, nil
}

// headerWriter lets cookie helpers written for http.ResponseWriter set
// headers of a Connect response.
type headerWriter http.Header

func (h headerWriter) Header() http.Header         { return http.Header(h) }
func (h headerWriter) Write(b []byte) (int, error) { return len(b), nil }
func (h headerWriter) WriteHeader(int)             {}
