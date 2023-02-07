package challenge

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kolide/krypto"
	"github.com/kolide/krypto/pkg/echelper"
	"github.com/vmihailenco/msgpack/v5"
)

type OuterResponse struct {
	// PublicEncryptionKey is the public half of the NaCL encryption key that was used to
	// ECDH the challenger provided PublicEncryptionKey
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	Sig                 []byte   `msgpack:"sig"`
	Sig2                []byte   `msgpack:"sig2"`
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

	if err := verifyWithKeyBytes(innerResponse.PublicSigningKey, innerResponseBytes, o.Sig); err != nil {
		return nil, fmt.Errorf("verifying challenge signature: %w", err)
	}

	// no sig 2 provided, return what we have
	if o.Sig2 == nil || len(o.Sig2) <= 0 {
		// if there is no sig2, set public signing key 2 to nil just in case so that
		// the consumer does not fasly assume it was used to perform a signature
		innerResponse.PublicSigningKey2 = nil
		return &innerResponse, nil
	}

	// got a signature 2, no public key 2
	if innerResponse.PublicSigningKey2 == nil || len(innerResponse.PublicSigningKey2) <= 0 {
		return nil, fmt.Errorf("have signature 2 but no public signing key 2")
	}

	if err := verifyWithKeyBytes(innerResponse.PublicSigningKey2, innerResponseBytes, o.Sig2); err != nil {
		return nil, fmt.Errorf("verifying challenge signature 2: %w", err)
	}

	return &innerResponse, nil
}

func verifyWithKeyBytes(keyBytes []byte, msg []byte, sig []byte) error {
	if strings.HasPrefix(string(keyBytes), "-----BEGIN PUBLIC KEY-----") {
		key, err := echelper.PublicPemToEcdsaKey(keyBytes)
		if err != nil {
			return err
		}
		return echelper.VerifySignature(*key, msg, sig)
	}

	keyStr, err := base64.StdEncoding.DecodeString(string(keyBytes))
	if err != nil {
		return fmt.Errorf("base64 decoding public der key: %w", err)
	}

	key, err := echelper.PublicDerToEcdsaKey(keyStr)
	if err != nil {
		return err
	}

	return echelper.VerifySignature(*key, msg, sig)
}

type InnerResponse struct {
	PublicSigningKey  []byte `msgpack:"publicSigningKey"`
	PublicSigningKey2 []byte `msgpack:"publicSigningKey2"`
	ChallengeData     []byte `msgpack:"challengeData"`
	ResponseData      []byte `msgpack:"responseData"`
	Timestamp         int64  `msgpack:"timestamp"`
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
