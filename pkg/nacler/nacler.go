package nacler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type Keyer interface {
	SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error)
	PublicKey() (ecdsa.PublicKey, error)
}

type Nacler struct {
	keyer        Keyer
	counterParty ecdsa.PublicKey
	sharedKey    [32]byte
}

func New(keyer Keyer, counterParty ecdsa.PublicKey) (*Nacler, error) {
	sharedKey, err := keyer.SharedKey(counterParty)
	if err != nil {
		return nil, fmt.Errorf("generating shared key: %w", err)
	}

	return &Nacler{
		keyer:        keyer,
		counterParty: counterParty,
		sharedKey:    sharedKey,
	}, nil
}

func (n *Nacler) Seal(plainText []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return box.SealAfterPrecomputation(nonce[:], plainText, &nonce, &n.sharedKey), nil
}

func (n *Nacler) Open(cipherText []byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], cipherText[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, cipherText[24:], &decryptNonce, &n.sharedKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return decrypted, nil
}
