package challenge

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/kolide/krypto"
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

func OpenResponsePng(privateEncryptionKey [32]byte, pngData []byte) (*InnerResponse, error) {
	var out bytes.Buffer
	in := bytes.NewBuffer(pngData)
	if err := krypto.FromPng(in, &out); err != nil {
		return nil, fmt.Errorf("decoding png data: %w", err)
	}

	var outerResponse OuterResponse
	if err := msgpack.Unmarshal(out.Bytes(), &outerResponse); err != nil {
		return nil, fmt.Errorf("unmarshaling outer box: %w", err)
	}

	innerResponse, err := OpenResponse(privateEncryptionKey, outerResponse)
	if err != nil {
		return nil, err
	}

	return innerResponse, nil
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

	counterPartyPubKey, err := publicPemToEcdsaKey(innerResponse.PublicSigningKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public ecdsa signing key from pem: %w", err)
	}

	if err := VerifySignature(*counterPartyPubKey, innerResponseBytes, responseOuter.Signature); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	return &innerResponse, nil
}
