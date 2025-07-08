package challenge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/kolide/krypto"
	"github.com/kolide/krypto/pkg/echelper"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/nacl/box"
)

const (
	signingTimeoutDuration = 1 * time.Second
	signingTimeoutInterval = 250 * time.Millisecond
)

type OuterChallenge struct {
	Sig            []byte `msgpack:"sig"`
	Msg            []byte `msgpack:"msg"`
	innerChallenge *InnerChallenge
}

func (o *OuterChallenge) Verify(counterParty ecdsa.PublicKey) error {
	if err := echelper.VerifySignature(&counterParty, o.Msg, o.Sig); err != nil {
		return err
	}

	innerChallenge, err := o.inner()
	if err != nil {
		return err
	}

	o.innerChallenge = innerChallenge
	return nil
}

func (o *OuterChallenge) RequestData() []byte {
	if o.innerChallenge != nil {
		return o.innerChallenge.RequestData
	}

	return nil
}

func (o *OuterChallenge) Timestamp() int64 {
	if o.innerChallenge != nil {
		return o.innerChallenge.Timestamp
	}

	return -1
}

func (o *OuterChallenge) Marshal() ([]byte, error) {
	return msgpack.Marshal(o)
}

// Respond creates a response to the challenge. It accepts crypto.Signer for signing, the second one may be nil.
// If the second signer is not nil and produces an error while signing, it will not be included nor will an error
// be returned. This is because the second signer is intended to be a TPM or Secure Enclave which we have found to be
// unreliable in testing.
func (o *OuterChallenge) Respond(signer crypto.Signer, signer2 crypto.Signer, responseData []byte) ([]byte, error) {
	if o.innerChallenge == nil {
		return nil, fmt.Errorf("no inner. unverified?")
	}

	ecdsaPubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signer pubkey in unexpected format (expected ECDSA, got %T)", signer.Public())
	}

	pubSigningDer, err := echelper.PublicEcdsaToB64Der(ecdsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling public signing key to der: %w", err)
	}

	var pubSigningKey2Der []byte
	if signer2 != nil {
		ecdsaPubKey2, ok := signer2.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signer pubkey 2 in unexpected format (expected ECDSA, got %T)", signer2.Public())
		}

		pubSigningKey2Der, err = echelper.PublicEcdsaToB64Der(ecdsaPubKey2)
		if err != nil {
			return nil, fmt.Errorf("marshalling public signing 2 key to der: %w", err)
		}
	}

	innerResponse, err := msgpack.Marshal(InnerResponse{
		PublicSigningKey:  pubSigningDer,
		PublicSigningKey2: pubSigningKey2Der,
		ChallengeData:     o.innerChallenge.ChallengeData,
		ResponseData:      responseData,
		Timestamp:         time.Now().Unix(),
	})

	if err != nil {
		return nil, fmt.Errorf("marshaling inner box: %w", err)
	}

	signature, err := echelper.SignWithTimeout(signer, innerResponse, signingTimeoutDuration, signingTimeoutInterval)
	if err != nil {
		return nil, fmt.Errorf("signing challenge: %w", err)
	}

	var signature2 []byte
	if signer2 != nil {
		// Intentionally ignoring errors here because we use the second signature to sign with a TPM or Secure Enclave,
		// we have found both of these to be unreliable in testing and we are not using them in any meaningful way.
		//nolint: errcheck - we allow nil signer2
		signature2, _ = echelper.SignWithTimeout(signer2, innerResponse, signingTimeoutDuration, signingTimeoutInterval)
	}

	sealed, pub, err := echelper.SealNaCl(innerResponse, &o.innerChallenge.PublicEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("sealing challenge inner box: %w", err)
	}

	outerResponse := &OuterResponse{
		PublicEncryptionKey: *pub,
		Sig:                 signature,
		Sig2:                signature2,
		Msg:                 sealed,
		ChallengeId:         o.innerChallenge.ChallengeId,
	}

	return msgpack.Marshal(outerResponse)
}

func (o *OuterChallenge) inner() (*InnerChallenge, error) {
	if o.Msg == nil {
		return nil, fmt.Errorf("inner is nil")
	}

	var inner InnerChallenge
	if err := msgpack.Unmarshal(o.Msg, &inner); err != nil {
		return nil, fmt.Errorf("unmarshaling inner challenge: %w", err)
	}
	return &inner, nil
}

func (o *OuterChallenge) RespondPng(signer crypto.Signer, signer2 crypto.Signer, responseData []byte) ([]byte, error) {
	response, err := o.Respond(signer, signer2, responseData)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := krypto.ToPng(&buf, response); err != nil {
		return nil, fmt.Errorf("encoding data to png: %w", err)
	}

	return buf.Bytes(), nil
}

func UnmarshalChallenge(outerChallengeBytes []byte) (*OuterChallenge, error) {
	if len(outerChallengeBytes) > krypto.V0MaxSize {
		return nil, fmt.Errorf("challenge exceeds max size: %d, max is %d", len(outerChallengeBytes), krypto.V0MaxSize)
	}

	var outerChallenge OuterChallenge
	if err := msgpack.Unmarshal(outerChallengeBytes, &outerChallenge); err != nil {
		return nil, err
	}
	return &outerChallenge, nil
}

type InnerChallenge struct {
	// PublicEncryptionKey is the public half of the NaCl encryption key to be used by the
	// responder to NaCl seal the response
	PublicEncryptionKey [32]byte `msgpack:"publicEncryptionKey"`
	ChallengeData       []byte   `msgpack:"challengeData"`
	RequestData         []byte   `msgpack:"requestData"`
	Timestamp           int64    `msgpack:"timestamp"`
	ChallengeId         []byte   `msgpack:"challengeId"`
}

func Generate(signer crypto.Signer, challengeId []byte, challengeData []byte, requestData []byte) ([]byte, *[32]byte, error) {
	pubEncKey, privEncKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encryption keys: %w", err)
	}

	inner, err := msgpack.Marshal(InnerChallenge{
		PublicEncryptionKey: *pubEncKey,
		ChallengeData:       challengeData,
		Timestamp:           time.Now().Unix(),
		ChallengeId:         challengeId,
		RequestData:         requestData,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("marshaling inner challenge box: %w", err)
	}

	signature, err := echelper.SignWithTimeout(signer, inner, signingTimeoutDuration, signingTimeoutInterval)
	if err != nil {
		return nil, nil, fmt.Errorf("signing challenge: %w", err)
	}

	outerChallenge := &OuterChallenge{
		Sig: signature,
		Msg: inner,
	}

	outerChallengeBytes, err := outerChallenge.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling outer challenge: %w", err)
	}

	return outerChallengeBytes, privEncKey, nil
}
