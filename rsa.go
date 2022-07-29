package krypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //#nosec G505 -- Need compatibility
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

func RsaEncrypt(key *rsa.PublicKey, secretMessage []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Cannot encrypt with a nil key")
	}

	//#nosec G401 -- Need compatibility
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, secretMessage, nil)
}

func RsaDecrypt(key *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Cannot decrypt with a nil key")
	}

	//#nosec G401 -- Need compatibility
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, key, ciphertext, nil)
}

func RsaSign(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Cannot sign with a nil key")
	}

	hasher := sha256.New()
	if _, err := hasher.Write(message); err != nil {
		return nil, fmt.Errorf("hashing message: %w", err)
	}
	digest := hasher.Sum(nil)

	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, nil)
}

func RsaVerify(key *rsa.PublicKey, message []byte, sig []byte) error {
	if key == nil {
		return errors.New("Cannot verify with a nil key")
	}

	hasher := sha256.New()
	if _, err := hasher.Write(message); err != nil {
		return fmt.Errorf("hashing message: %w", err)
	}
	digest := hasher.Sum(nil)

	return rsa.VerifyPSS(key, crypto.SHA256, digest, sig, nil)
}

// RsaFingerprint returns the SHA256 fingerprint. This is calculated
// by hashing the DER representation of the public key. It is
// analogous to `openssl rsa -in key.pem -pubout -outform DER | openssl sha256 -c``
func RsaFingerprint(keyRaw interface{}) (string, error) {
	var pub *rsa.PublicKey

	switch key := keyRaw.(type) {
	case *rsa.PrivateKey:
		pub = key.Public().(*rsa.PublicKey)
	case *rsa.PublicKey:
		pub = key
	default:
		return "", errors.New("cannot fingerprint that type")
	}

	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshalling to PKIX: %w", err)
	}

	sum := sha256.Sum256(pkix)

	out := ""
	for i := 0; i < 32; i++ {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02x", sum[i])
	}

	return out, nil
}

func RsaRandomKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func RsaPrivateKeyToPem(key *rsa.PrivateKey, out io.Writer) error {
	privASN1 := x509.MarshalPKCS1PrivateKey(key)

	return pem.Encode(out, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})
}

func RsaPublicKeyToPem(key *rsa.PrivateKey, out io.Writer) error {
	pubASN1, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("pkix marshalling: %w", err)
	}

	return pem.Encode(out, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}

func KeyFromPem(pemRaw []byte) (interface{}, error) {
	// pem.Decode returns pem, and rest. No error here
	block, _ := pem.Decode(pemRaw)
	if block == nil || block.Type == "" {
		return nil, errors.New("got blank data from pem")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	}

	return nil, fmt.Errorf("Unknown block type: %s", block.Type)
}
