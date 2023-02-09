package echelper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

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

func PublicPemToEcdsaKey(keyBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(keyBytes)
	return PublicDerToEcdsaKey(block.Bytes)
}

func PublicB64DerToEcdsaKey(keyBytes []byte) (*ecdsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(keyBytes))
	if err != nil {
		return nil, err
	}
	return PublicDerToEcdsaKey(decoded)
}

func PublicDerToEcdsaKey(der []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing pkix public key: %w", err)
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an ECDSA public key")
	}
	return pub, nil
}

func PublicEcdsaToB64Der(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(der)), nil
}

func GenerateEcdsaKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func SignWithTimeout(signer crypto.Signer, data []byte, duration, interval time.Duration) ([]byte, error) {
	timeout := time.NewTimer(duration)
	intervalTicker := time.NewTicker(interval)
	attempts := 0

	for {
		signature, err := Sign(signer, data)
		if err == nil {
			return signature, nil
		}

		attempts++

		select {
		case <-timeout.C:
			return nil, fmt.Errorf("signing timed out after %d attempts, last error: %w", attempts, err)
		case <-intervalTicker.C:
			continue
		}
	}
}

func hashForSignature(data []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}
