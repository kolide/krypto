package keyencoder

import (
	"crypto/rsa"

	"github.com/kolide/krypto/pkg/rsafunc"
)

type keyEncoder struct {
	key *rsa.PrivateKey
}

func New(key *rsa.PrivateKey) *keyEncoder {
	return &keyEncoder{
		key: key,
	}
}

func (ke *keyEncoder) Sign(in []byte) ([]byte, error) {
	return rsafunc.Sign(ke.key, in)
}

func (ke *keyEncoder) PublicSigningKeyFingerprint() (string, error) {
	return rsafunc.Fingerprint(ke.key)
}

func (ke *keyEncoder) Decrypt(in []byte) ([]byte, error) {
	return rsafunc.Decrypt(ke.key, in)
}
