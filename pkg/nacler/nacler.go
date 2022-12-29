package nacler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type Keyer interface {
	SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error)
}

type Nacler struct {
	keyer        Keyer
	counterParty ecdsa.PublicKey
}

func New(keyer Keyer, counterParty ecdsa.PublicKey) *Nacler {
	return &Nacler{
		keyer:        keyer,
		counterParty: counterParty,
	}
}

func (n *Nacler) Seal(plainText []byte) (string, error) {
	sharedKey, err := n.keyer.SharedKey(n.counterParty)
	if err != nil {
		return "", fmt.Errorf("generating shared key: %w", err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	encrypted := box.SealAfterPrecomputation(nonce[:], plainText, &nonce, &sharedKey)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (n *Nacler) Open(b64 string) (string, error) {
	sharedKey, err := n.keyer.SharedKey(n.counterParty)
	if err != nil {
		return "", fmt.Errorf("generating shared key: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], raw[:24])

	decrypted, ok := box.OpenAfterPrecomputation(nil, raw[24:], &decryptNonce, &sharedKey)
	if !ok {
		return "", fmt.Errorf("decryption failed")
	}
	return string(decrypted), nil
}
