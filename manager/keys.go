package manager

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// PrincipalKeyComment is the comment of the principal public key.
const PrincipalKeyComment = "openpicket-principal"

// Keys derived from the host key, so that every replica agrees on them
// without more secrets: the static login session key and the key signing
// principal tokens for openpicket-suricontroller.
type Keys struct {
	Session   []byte
	Principal *sshkey.PrivateKey
}

// DeriveKeys derives the keys from the host key.
func DeriveKeys(host *sshkey.PrivateKey) (*Keys, error) {
	seed := host.Key.Seed()
	session, err := hkdf.Key(sha256.New, seed, nil, "openpicket/session/v1", 32)
	if err != nil {
		return nil, err
	}
	p, err := hkdf.Key(sha256.New, seed, nil, "openpicket/principal/v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return &Keys{Session: session, Principal: &sshkey.PrivateKey{Key: ed25519.NewKeyFromSeed(p)}}, nil
}
