package challenge

import (
	"bytes"
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
	ChallengeId         []byte   `msgpack:"challengeId"`
}

func (o *OuterResponse) Open(privateEncryptionKey [32]byte) (*InnerResponse, error) {
	innerResponseBytes, err := echelper.OpenNaCl(o.Msg, &o.PublicEncryptionKey, &privateEncryptionKey)
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

	if err := echelper.VerifySignature(*counterPartyPubKey, innerResponseBytes, o.Sig); err != nil {
		return nil, fmt.Errorf("verifying challenge: %w", err)
	}

	return &innerResponse, nil
}

type InnerResponse struct {
	PublicSigningKey []byte `msgpack:"publicSigningKey"`
	ChallengeData    []byte `msgpack:"challengeData"`
	ResponseData     []byte `msgpack:"responseData"`
	Timestamp        int64  `msgpack:"timeStamp"`
}

func UnmarshalResponse(outerResponseBytes []byte) (*OuterResponse, error) {
	var outerResponse OuterResponse
	if err := msgpack.Unmarshal(outerResponseBytes, &outerResponse); err != nil {
		return nil, err
	}
	return &outerResponse, nil
}

func UnmarshalResponsePng(outerResponsePngBytes []byte) (*OuterResponse, error) {
	var out bytes.Buffer
	in := bytes.NewBuffer(outerResponsePngBytes)
	if err := krypto.FromPng(in, &out); err != nil {
		return nil, fmt.Errorf("decoding png data: %w", err)
	}

	return UnmarshalResponse(out.Bytes())
}
