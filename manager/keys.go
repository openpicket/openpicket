package manager

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// PrincipalKeyComment is the comment of the principal public key.
const PrincipalKeyComment = "openpicket-principal"

// Keys of the UI and API: the static login session key and the key
// signing principal tokens for openpicket-suricontroller. Every replica
// derives them from one secret (OPENPICKET_KEY_SECRET), so they agree
// without more secrets. Without that secret they come from the host key,
// as before the gateway split: then whoever holds the channel B host key
// (a gateway) can also forge sessions, so a split setup sets the secret.
type Keys struct {
	Session   []byte
	Principal *sshkey.PrivateKey
}

// DeriveKeys derives the keys from the host key (setups without
// OPENPICKET_KEY_SECRET).
func DeriveKeys(host *sshkey.PrivateKey) (*Keys, error) {
	return DeriveKeysFrom(host.Key.Seed())
}

// DeriveKeysFrom derives the keys from a secret.
func DeriveKeysFrom(secret []byte) (*Keys, error) {
	session, err := hkdf.Key(sha256.New, secret, nil, "openpicket/session/v1", 32)
	if err != nil {
		return nil, err
	}
	p, err := hkdf.Key(sha256.New, secret, nil, "openpicket/principal/v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return &Keys{Session: session, Principal: &sshkey.PrivateKey{Key: ed25519.NewKeyFromSeed(p)}}, nil
}
