package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// CookieName is the session cookie of the static login.
const CookieName = "openpicket_session"

// Static is the fixed username/password login. The session is a signed
// cookie (HMAC key shared by all replicas), so no session store exists.
type Static struct {
	Username     string
	PasswordHash []byte // bcrypt
	Role         string
	Key          []byte // cookie HMAC key, >= 32 bytes
	TTL          time.Duration
	// Insecure drops the Secure cookie attribute (plain HTTP setups).
	Insecure bool
	Now      func() time.Time

	dummy []byte
}

// NewStatic validates the configuration.
func NewStatic(username, passwordHash, role string, key []byte) (*Static, error) {
	if username == "" || passwordHash == "" {
		return nil, errors.New("auth: static: username and password hash are required")
	}
	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return nil, errors.New("auth: static: password hash is not bcrypt")
	}
	if len(key) < 32 {
		return nil, errors.New("auth: static: cookie key must be at least 32 bytes")
	}
	if role == "" {
		role = RoleAdmin
	}
	if _, ok := roleRank[role]; !ok {
		return nil, errors.New("auth: static: unknown role " + role)
	}
	dummy, _ := bcrypt.GenerateFromPassword([]byte("openpicket-timing"), bcrypt.MinCost)
	return &Static{Username: username, PasswordHash: []byte(passwordHash), Role: role, Key: key, TTL: 24 * time.Hour, dummy: dummy}, nil
}

// Name implements Provider.
func (s *Static) Name() string { return "static" }

func (s *Static) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type session struct {
	Sub   string   `json:"sub"`
	Roles []string `json:"roles"`
	Exp   int64    `json:"exp"`
}

var b64 = base64.RawURLEncoding

func (s *Static) sign(payload []byte) string {
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte("openpicket-session:"))
	m.Write(payload)
	return b64.EncodeToString(m.Sum(nil))
}

// Authenticate implements Provider.
func (s *Static) Authenticate(r *http.Request) (*Principal, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNoCredentials
	}
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, ErrInvalidCredentials
	}
	payload, err := b64.DecodeString(body)
	if err != nil || subtle.ConstantTimeCompare([]byte(sig), []byte(s.sign(payload))) != 1 {
		return nil, ErrInvalidCredentials
	}
	var sess session
	if json.Unmarshal(payload, &sess) != nil || s.now().Unix() > sess.Exp || sess.Sub != s.Username {
		return nil, ErrInvalidCredentials
	}
	return &Principal{Subject: sess.Sub, Name: sess.Sub, Roles: sess.Roles, Cookie: true}, nil
}

// Login implements PasswordLogin. Comparison time does not reveal whether
// the user name was right.
func (s *Static) Login(_ context.Context, username, password string) (*Principal, error) {
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.Username)) != 1 {
		_ = bcrypt.CompareHashAndPassword(s.dummy, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword(s.PasswordHash, []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}
	return &Principal{Provider: s.Name(), Subject: s.Username, Name: s.Username, Roles: []string{s.Role}}, nil
}

// IssueSession implements SessionIssuer.
func (s *Static) IssueSession(w http.ResponseWriter, p *Principal) error {
	payload, err := json.Marshal(session{Sub: p.Subject, Roles: p.Roles, Exp: s.now().Add(s.TTL).Unix()})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: b64.EncodeToString(payload) + "." + s.sign(payload), Path: "/",
		MaxAge: int(s.TTL / time.Second), HttpOnly: true, Secure: !s.Insecure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// ClearSession implements SessionIssuer.
func (s *Static) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !s.Insecure, SameSite: http.SameSiteStrictMode})
}
