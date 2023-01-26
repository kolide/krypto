package challenge

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/kolide/krypto"
	"github.com/kolide/krypto/pkg/echelper"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/nacl/box"
)

type OuterChallenge struct {
	Sig []byte `msgpack:"sig"`
	Msg []byte `msgpack:"msg"`
}

type InnerChallenge struct {
	// PublicEncryptionKey is the public half of the NaCl encryption key to be used by the
	// responder to NaCl seal the response
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	ChallengeData       []byte   `msgpack:"challengeData"`
	TimeStamp           int64    `msgpack:"timeStamp"`
	ChallengeId         []byte   `msgpack:"challengeId"`
}

func Generate(signer crypto.Signer, challengeId []byte, challengeData []byte) (*OuterChallenge, *[32]byte, error) {
	pubEncKey, privEncKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encryption keys: %w", err)
	}

	inner, err := msgpack.Marshal(InnerChallenge{
		PublicEncryptionKey: *pubEncKey,
		ChallengeData:       challengeData,
		TimeStamp:           time.Now().Unix(),
		ChallengeId:         challengeId,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("marshaling inner challenge box: %w", err)
	}

	signature, err := echelper.Sign(signer, inner)
	if err != nil {
		return nil, nil, fmt.Errorf("signing challenge: %w", err)
	}

	return &OuterChallenge{
		Sig: signature,
		Msg: inner,
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

	return OpenResponse(privateEncryptionKey, outerResponse)
}

func OpenResponse(privateEncryptionKey [32]byte, responseOuter OuterResponse) (*InnerResponse, error) {
	innerResponseBytes, err := echelper.OpenNaCl(responseOuter.Msg, &responseOuter.PublicEncryptionKey, &privateEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("opening challenge response box: %w", err)
	}

	var innerResponse InnerResponse
	if err := msgpack.Unmarshal(innerResponseBytes, &innerResponse); err != nil {
		return nil, fmt.Errorf("unmarshaling inner box: %w", err)
	}

	counterPartyPubKey, err := echelper.PublicPemToEcdsaKey(innerResponse.PublicSigningKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public ecdsa signing key from pem: %w", err)
	}

	if err := echelper.VerifySignature(*counterPartyPubKey, innerResponseBytes, responseOuter.Sig); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	return &innerResponse, nil
}
