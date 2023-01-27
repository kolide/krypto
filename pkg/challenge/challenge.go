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

type OuterChallenge struct {
	Sig            []byte `msgpack:"sig"`
	Msg            []byte `msgpack:"msg"`
	innerChallenge *InnerChallenge
}

func (o *OuterChallenge) Verify(counterParty ecdsa.PublicKey) error {
	if err := echelper.VerifySignature(counterParty, o.Msg, o.Sig); err != nil {
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

func (o *OuterChallenge) Respond(signer crypto.Signer, responseData []byte) ([]byte, error) {
	innerChallenge, err := o.inner()
	if err != nil {
		return nil, err
	}

	pubSigningKeyPem, err := echelper.PublicEcdsaKeyToPem(signer.Public().(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("marshalling public signing key to pem: %w", err)
	}

	innerResponse, err := msgpack.Marshal(InnerResponse{
		PublicSigningKey: pubSigningKeyPem,
		ChallengeData:    innerChallenge.ChallengeData,
		ResponseData:     responseData,
		Timestamp:        time.Now().Unix(),
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

	outerResponse := &OuterResponse{
		PublicEncryptionKey: *pub,
		Sig:                 signature,
		Msg:                 sealed,
		ChallengeId:         innerChallenge.ChallengeId,
	}

	return msgpack.Marshal(outerResponse)
}

func (o *OuterChallenge) inner() (*InnerChallenge, error) {
	var inner InnerChallenge
	if err := msgpack.Unmarshal(o.Msg, &inner); err != nil {
		return nil, fmt.Errorf("unmarshaling inner challenge: %w", err)
	}
	return &inner, nil
}

func (o *OuterChallenge) RespondPng(signer crypto.Signer, responseData []byte) ([]byte, error) {
	response, err := o.Respond(signer, responseData)
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

	signature, err := echelper.Sign(signer, inner)
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
