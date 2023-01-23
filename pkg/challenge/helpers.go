package challenge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func Sign(signer crypto.Signer, data []byte) ([]byte, error) {
	digest, err := hashForSignature(data)
	if err != nil {
		return nil, fmt.Errorf("hashing data: %w", err)
	}

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return signature, nil
}

func VerifySignature(counterParty ecdsa.PublicKey, data []byte, signature []byte) error {
	digest, err := hashForSignature(data)
	if err != nil {
		return fmt.Errorf("hashing inner box: %w", err)
	}

	if !ecdsa.VerifyASN1(&counterParty, digest, signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func SealNaCl(data []byte, counterPartyPublicKey *[32]byte) ([]byte, *[32]byte, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encryption keys: %w", err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	sealed := box.Seal(nonce[:], data, &nonce, counterPartyPublicKey, priv)

	return sealed, pub, nil
}

func OpenNaCl(sealed []byte, counterPartyPublicKey, privateKey *[32]byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], sealed[:24])

	opened, ok := box.Open(nil, sealed[24:], &decryptNonce, counterPartyPublicKey, privateKey)
	if !ok {
		return nil, errors.New("opening inner box")
	}

	return opened, nil
}

func hashForSignature(data []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func publicEcdsaKeyToPem(pub *ecdsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes}), nil
}

func publicPemToEcdsaKey(keyBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(keyBytes)

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an ECDSA public key")
	}
	return pub, nil
}
