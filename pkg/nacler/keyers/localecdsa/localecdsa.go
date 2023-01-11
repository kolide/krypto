package localecdsa

import (
	"crypto/ecdsa"
	"crypto/sha256"
)

type localecdsa struct {
	key *ecdsa.PrivateKey
}

func New(key *ecdsa.PrivateKey) *localecdsa {
	return &localecdsa{
		key: key,
	}
}

func (l *localecdsa) SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error) {
	// code adapted from https://asecuritysite.com/ecc/goecdh
	// thank you Bill Buchanan!
	generated, _ := counterParty.Curve.ScalarMult(counterParty.X, counterParty.Y, l.key.D.Bytes())
	return sha256.Sum256(generated.Bytes()), nil
}

func (l *localecdsa) PublicKey() (ecdsa.PublicKey, error) {
	return l.key.PublicKey, nil
}
