package challenge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/kolide/krypto"
	"github.com/kolide/krypto/pkg/echelper"
	"github.com/vmihailenco/msgpack/v5"
)

type OuterResponse struct {
	// PublicEncryptionKey is the public half of the NaCL encryption key that was used to
	// ECDH the challenger provided PublicEncryptionKey
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	Sig                 []byte   `msgpack:"sig"`
	Msg                 []byte   `msgpack:"msg"`
}

type InnerResponse struct {
	PublicSigningKey []byte `msgpack:"publicSigningKey"`
	ChallengeData    []byte `msgpack:"challengeData"`
	ResponseData     []byte `msgpack:"responseData"`
}

func RespondPng(signer crypto.Signer, counterParty ecdsa.PublicKey, challengeOuter OuterChallenge, responseData []byte) ([]byte, error) {
	response, err := Respond(signer, counterParty, challengeOuter, responseData)
	if err != nil {
		return nil, err
	}

	packedResponse, err := msgpack.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %w", err)
	}

	var buf bytes.Buffer
	if err := krypto.ToPng(&buf, packedResponse); err != nil {
		return nil, fmt.Errorf("encoding data to png")
	}

	return buf.Bytes(), nil
}

func Respond(signer crypto.Signer, counterParty ecdsa.PublicKey, challengeOuter OuterChallenge, responseData []byte) (*OuterResponse, error) {
	if err := echelper.VerifySignature(counterParty, challengeOuter.Msg, challengeOuter.Sig); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	var innerChallenge InnerChallenge
	if err := msgpack.Unmarshal(challengeOuter.Msg, &innerChallenge); err != nil {
		return nil, fmt.Errorf("unmarshaling inner box: %w", err)
	}

	pubSigningKeyPem, err := echelper.PublicEcdsaKeyToPem(signer.Public().(*ecdsa.PublicKey))
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

	signature, err := echelper.Sign(signer, innerResponse)
	if err != nil {
		return nil, fmt.Errorf("signing challenge: %w", err)
	}

	sealed, pub, err := echelper.SealNaCl(innerResponse, &innerChallenge.PublicEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("sealing challenge inner box: %w", err)
	}

	return &OuterResponse{
		PublicEncryptionKey: *pub,
		Sig:                 signature,
		Msg:                 sealed,
	}, nil
}
