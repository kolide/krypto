package krypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

func RsaEncrypt(key *rsa.PublicKey, secretMessage []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, secretMessage, nil)
}

func RsaDecrypt(key *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, key, ciphertext, nil)
}

func RsaSign(key *rsa.PrivateKey, message []byte) ([]byte, error) {
	hasher := sha256.New()
	if _, err := hasher.Write(message); err != nil {
		return nil, fmt.Errorf("hashing message: %w", err)
	}
	digest := hasher.Sum(nil)

	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, nil)
}

func RsaVerify(key *rsa.PublicKey, message []byte, sig []byte) error {
	hasher := sha256.New()
	if _, err := hasher.Write(message); err != nil {
		return fmt.Errorf("hashing message: %w", err)
	}
	digest := hasher.Sum(nil)

	return rsa.VerifyPSS(key, crypto.SHA256, digest, sig, nil)
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
		return fmt.Errorf("pkix marshalling: %w")
	}

	return pem.Encode(out, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}
