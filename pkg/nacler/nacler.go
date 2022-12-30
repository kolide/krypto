package nacler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type keyer interface {
	SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error)
}

type Nacler struct {
	keyer        keyer
	counterParty ecdsa.PublicKey
}

func New(keyer keyer, counterParty ecdsa.PublicKey) *Nacler {
	return &Nacler{
		keyer:        keyer,
		counterParty: counterParty,
	}
}

func (n *Nacler) Seal(plainText []byte) ([]byte, error) {
	sharedKey, err := n.keyer.SharedKey(n.counterParty)
	if err != nil {
		return nil, fmt.Errorf("generating shared key: %w", err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return box.SealAfterPrecomputation(nonce[:], plainText, &nonce, &sharedKey), nil
}

func (n *Nacler) Open(cipherText []byte) ([]byte, error) {
	sharedKey, err := n.keyer.SharedKey(n.counterParty)
	if err != nil {
		return nil, fmt.Errorf("generating shared key: %w", err)
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], cipherText[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, cipherText[24:], &decryptNonce, &sharedKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return decrypted, nil
}
