package principal

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	tok, err := Mint(priv, AudienceSuricontroller, "static:admin", "Admin", []string{RoleAdmin}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(pub, tok, AudienceSuricontroller, now.Add(30*time.Second))
	if err != nil || c.Subject != "static:admin" || !c.HasRole(RoleAdmin) || c.HasRole(RoleViewer) {
		t.Fatalf("claims = %+v, %v", c, err)
	}
	if _, err := Verify(pub, tok, AudienceSuricontroller, now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := Verify(pub, tok, "other", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("audience: %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(otherPub, tok, AudienceSuricontroller, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"x","roles":["admin"],"aud":"openpicket-suricontroller","exp":9999999999}`)) + "." + parts[2]
	if _, err := Verify(pub, forged, AudienceSuricontroller, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged payload: %v", err)
	}
	none := b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	if _, err := Verify(pub, none, AudienceSuricontroller, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("alg none: %v", err)
	}
}
