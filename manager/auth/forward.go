package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// Forward asks an external verify endpoint (nginx auth_request style) for
// every request: the client's cookies and Authorization header are
// forwarded, a 2xx answer identifies the user through its response
// headers. Answers are cached briefly per credential.
type Forward struct {
	ProviderName string
	URL          string
	UserHeader   string
	NameHeader   string
	EmailHeader  string
	GroupsHeader string
	GroupsSep    string
	CacheTTL     time.Duration
	Login        string
	Logout       string
	HTTPClient   *http.Client
	Now          func() time.Time

	mu    sync.Mutex
	cache map[string]forwardEntry
}

type forwardEntry struct {
	p   *Principal
	err error
	exp time.Time
}

// Validate checks the configuration.
func (f *Forward) Validate() error {
	if f.URL == "" || f.UserHeader == "" {
		return errors.New("auth: forward: url and user header are required")
	}
	return nil
}

// Name implements Provider.
func (f *Forward) Name() string {
	if f.ProviderName != "" {
		return f.ProviderName
	}
	return "forward"
}

func (f *Forward) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Authenticate implements Provider.
func (f *Forward) Authenticate(r *http.Request) (*Principal, error) {
	cookie, authz := r.Header.Get("Cookie"), r.Header.Get("Authorization")
	if cookie == "" && authz == "" {
		return nil, ErrNoCredentials
	}
	sum := sha256.Sum256([]byte(cookie + "\x00" + authz))
	key := hex.EncodeToString(sum[:])
	ttl := f.CacheTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]forwardEntry{}
	}
	if e, ok := f.cache[key]; ok && f.now().Before(e.exp) {
		f.mu.Unlock()
		if e.err != nil {
			return nil, e.err
		}
		cp := *e.p
		return &cp, nil
	}
	f.mu.Unlock()
	p, err := f.verify(r, cookie, authz)
	if err != nil && !errors.Is(err, ErrInvalidCredentials) && !errors.Is(err, ErrNoCredentials) {
		return nil, err // verify endpoint unavailable: do not cache
	}
	f.mu.Lock()
	for k, e := range f.cache {
		if f.now().After(e.exp) {
			delete(f.cache, k)
		}
	}
	f.cache[key] = forwardEntry{p: p, err: err, exp: f.now().Add(ttl)}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	cp := *p
	return &cp, nil
}

func (f *Forward) verify(r *http.Request, cookie, authz string) (*Principal, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	req.Header.Set("X-Forwarded-Host", r.Host)
	client := f.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode/100 == 3:
		return nil, ErrNoCredentials
	case resp.StatusCode/100 != 2:
		return nil, errors.New("auth: forward: verify endpoint status " + resp.Status)
	}
	user := resp.Header.Get(f.UserHeader)
	if user == "" {
		return nil, ErrInvalidCredentials
	}
	p := &Principal{Subject: user, Name: user, Cookie: cookie != "" && authz == ""}
	if f.NameHeader != "" && resp.Header.Get(f.NameHeader) != "" {
		p.Name = resp.Header.Get(f.NameHeader)
	}
	if f.EmailHeader != "" {
		p.Email = resp.Header.Get(f.EmailHeader)
	}
	if f.GroupsHeader != "" {
		p.Groups = splitGroups(resp.Header.Get(f.GroupsHeader), f.GroupsSep)
	}
	return p, nil
}

// LoginURL implements ExternalLogin.
func (f *Forward) LoginURL(string) string { return f.Login }

// LogoutURL implements ExternalLogin.
func (f *Forward) LogoutURL() string { return f.Logout }
