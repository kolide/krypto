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

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/nacl/box"
)

type OuterChallenge struct {
	Signature []byte `msgpack:"signature"`
	Inner     []byte `msgpack:"inner"`
}

type InnerChallenge struct {
	// PublicEncryptionKey is the public half of the NaCl encryption key to be used by the
	// responder to NaCl seal the response
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	ChallengeData       []byte   `msgpack:"challengeData"`
}

func Generate(signer crypto.Signer, challengeData []byte) (*OuterChallenge, *[32]byte, error) {
	pubEncKey, privEncKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encryption keys: %w", err)
	}

	inner, err := msgpack.Marshal(InnerChallenge{
		PublicEncryptionKey: *pubEncKey,
		ChallengeData:       challengeData,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("marshaling inner challenge box: %w", err)
	}

	signature, err := Sign(signer, inner)
	if err != nil {
		return nil, nil, fmt.Errorf("signing challenge: %w", err)
	}

	return &OuterChallenge{
		Signature: signature,
		Inner:     inner,
	}, privEncKey, nil
}

type OuterResponse struct {
	// PublicEncryptionKey is the public half of the NaCL encryption key that was used to
	// ECDH the challenger provided PublicEncryptionKey
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	Signature           []byte   `msgpack:"signature"`
	Inner               []byte   `msgpack:"inner"`
}

type InnerResponse struct {
	PublicSigningKey []byte `msgpack:"publicSigningKey"`
	ChallengeData    []byte `msgpack:"challengeData"`
	ResponseData     []byte `msgpack:"responseData"`
}

func Respond(signer crypto.Signer, counterParty ecdsa.PublicKey, challengeOuter OuterChallenge, responseData []byte) (*OuterResponse, error) {
	if err := VerifySignature(counterParty, challengeOuter.Inner, challengeOuter.Signature); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	var innerChallenge InnerChallenge
	if err := msgpack.Unmarshal(challengeOuter.Inner, &innerChallenge); err != nil {
		return nil, fmt.Errorf("unmarshaling inner box: %w", err)
	}

	pubSigningKeyPem, err := publicEcdsaKeyToPem(signer.Public().(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("marshalling public signing key to pem: %w", err)
	}

	innerResponse, err := msgpack.Marshal(InnerResponse{
		PublicSigningKey: pubSigningKeyPem,
		ChallengeData:    innerChallenge.ChallengeData,
		ResponseData:     responseData,
	})

	if err != nil {
		return nil, fmt.Errorf("marshaling inner box: %w", err)
	}

	signature, err := Sign(signer, innerResponse)
	if err != nil {
		return nil, fmt.Errorf("signing challenge: %w", err)
	}

	sealed, pub, err := SealNaCl(innerResponse, &innerChallenge.PublicEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("sealing challenge inner box: %w", err)
	}

	return &OuterResponse{
		PublicEncryptionKey: *pub,
		Signature:           signature,
		Inner:               sealed,
	}, nil
}

func OpenResponse(privateEncryptionKey [32]byte, responseOuter OuterResponse) (*InnerResponse, error) {
	innerResponseBytes, err := OpenNaCl(responseOuter.Inner, &responseOuter.PublicEncryptionKey, &privateEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("opening challenge response box: %w", err)
	}

	var innerResponse InnerResponse
	if err := msgpack.Unmarshal(innerResponseBytes, &innerResponse); err != nil {
		return nil, fmt.Errorf("unmarshaling inner box: %w", err)
	}

	counterPartyPubKey, err := publicPemToEcKey(innerResponse.PublicSigningKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public ecdsa signing key from pem: %w", err)
	}

	if err := VerifySignature(*counterPartyPubKey, innerResponseBytes, responseOuter.Signature); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	return &innerResponse, nil
}

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

func publicPemToEcKey(keyBytes []byte) (*ecdsa.PublicKey, error) {
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
