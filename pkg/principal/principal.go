// Package principal carries an authenticated OpenPicket user from
// openpicket-manager to openpicket-suricontroller.
//
// The manager authenticates the browser (its own auth chain), then proxies
// /suricata/ requests with a short-lived token in the Header. The token is a
// JWS compact serialization signed with Ed25519 ("EdDSA"); the manager holds
// the private key and openpicket-suricontroller the public key.
package principal

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Header is the request header holding the token.
const Header = "X-OpenPicket-Principal"

// AudienceSuricontroller is the audience of tokens for
// openpicket-suricontroller.
const AudienceSuricontroller = "openpicket-suricontroller"

// DefaultTTL is the lifetime of a token minted for one proxied request.
const DefaultTTL = time.Minute

// Roles.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// Claims identify the user.
type Claims struct {
	// Subject is "provider:subject" (stable user id).
	Subject  string   `json:"sub"`
	Name     string   `json:"name,omitempty"`
	Roles    []string `json:"roles"`
	Audience string   `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// HasRole reports whether the claims include role.
func (c *Claims) HasRole(role string) bool { return slices.Contains(c.Roles, role) }

var (
	// ErrInvalid is returned for a malformed or wrongly signed token.
	ErrInvalid = errors.New("principal: invalid token")
	// ErrExpired is returned for an expired token.
	ErrExpired = errors.New("principal: token expired")
)

var b64 = base64.RawURLEncoding

const header = `{"alg":"EdDSA","typ":"JWT"}`

// Sign returns a token for c.
func Sign(key ed25519.PrivateKey, c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(payload)
	return signing + "." + b64.EncodeToString(ed25519.Sign(key, []byte(signing))), nil
}

// Mint signs a token for subject valid for ttl from now.
func Mint(key ed25519.PrivateKey, audience, subject, name string, roles []string, ttl time.Duration, now time.Time) (string, error) {
	return Sign(key, Claims{Subject: subject, Name: name, Roles: roles, Audience: audience, IssuedAt: now.Unix(), Expiry: now.Add(ttl).Unix()})
}

// Verify checks the signature, audience and expiry of token.
func Verify(pub ed25519.PublicKey, token, audience string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalid
	}
	hdr, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalid
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "EdDSA" {
		return nil, ErrInvalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrInvalid
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrInvalid
	}
	if c.Audience != audience {
		return nil, fmt.Errorf("%w: audience %q", ErrInvalid, c.Audience)
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrInvalid)
	}
	// Allow a little clock difference between replicas.
	if now.Unix() > c.Expiry+5 {
		return nil, ErrExpired
	}
	return &c, nil
}
