package krypto

import (
	"bytes"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kolide/kit/ulid"
	"github.com/vmihailenco/msgpack/v5"
)

type outerBox struct {
	Inner     []byte `msgpack:"inner"`
	Signature []byte `msgpack:"signature"`
	Sender    string `msgpack:"sender"`
}

// Box holds data. Note that most of these fields are metadata. And while that is signed,
// verification of the signature is up to the recipient. Caution is especially merited
// around the Sender field. It can be seen as an arbitrary string.
type Box struct {
	// These fields are the packed, signed, etc data.
	Version    int    `msgpack:"version"`
	Timestamp  int64  `msgpack:"timestamp"`
	Key        []byte `msgpack:"key"`
	Ciphertext []byte `msgpack:"ciphertext"`
	Signedtext []byte `msgpack:"signedtext"`
	RequestId  string `msgpack:"requestid"`
	ResponseTo string `msgpack:"responseto"`

	// These fields are used as internal fields, not part of the packed data. Thus, not exported.
	data   []byte
	sender string
}

func (inner Box) Data() []byte { return inner.data }

func (inner Box) Sender() string { return inner.sender }

type boxMaker struct {
	key          *rsa.PrivateKey
	counterparty *rsa.PublicKey
}

func NewBoxer(key *rsa.PrivateKey, counterparty *rsa.PublicKey) boxMaker {
	return boxMaker{
		key:          key,
		counterparty: counterparty,
	}
}

func (boxer boxMaker) Encode(inResponseTo string, data []byte) (string, error) {
	raw, err := boxer.EncodeRaw(inResponseTo, data)
	if err != nil {
		return "", fmt.Errorf("encoding raw: %w", err)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

func (boxer boxMaker) EncodePng(inResponseTo string, data []byte, w io.Writer) error {
	raw, err := boxer.EncodeRaw(inResponseTo, data)
	if err != nil {
		return fmt.Errorf("encoding raw: %w", err)
	}

	return ToPng(w, raw)
}

func (boxer boxMaker) EncodeRaw(inResponseTo string, data []byte) ([]byte, error) {
	aeskey, err := AesRandomKey()
	if err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}

	aeskeyEnc, err := RsaEncrypt(boxer.counterparty, aeskey)
	if err != nil {
		return nil, fmt.Errorf("encrypting DEK: %w", err)
	}

	ciphertext, err := AesEncrypt(aeskey, nil, data)
	if err != nil {
		return nil, fmt.Errorf("encrypting data: %w", err)
	}

	fingerprint, err := RsaFingerprint(boxer.key)
	if err != nil {
		return nil, fmt.Errorf("unable to fingerprint: %w", err)
	}

	inner := Box{
		Version:    1,
		Timestamp:  time.Now().Unix(),
		Key:        aeskeyEnc,
		Ciphertext: ciphertext,
		RequestId:  ulid.New(),
		ResponseTo: inResponseTo,
	}

	innerPacked, err := msgpack.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("packing inner: %w", err)
	}

	innerSig, err := RsaSign(boxer.key, innerPacked)
	if err != nil {
		return nil, fmt.Errorf("signing inner: %w", err)
	}

	outer := outerBox{
		Inner:     innerPacked,
		Signature: innerSig,
		Sender:    fingerprint,
	}

	outerPacked, err := msgpack.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("packing outer: %w", err)
	}

	return outerPacked, nil
}

func (boxer boxMaker) Sign(inResponseTo string, data []byte) ([]byte, error) {
	fingerprint, err := RsaFingerprint(boxer.key)
	if err != nil {
		return nil, fmt.Errorf("unable to fingerprint: %w", err)
	}

	inner := Box{
		Version:    1,
		Timestamp:  time.Now().Unix(),
		Signedtext: data,
		RequestId:  ulid.New(),
		ResponseTo: inResponseTo,
	}

	innerPacked, err := msgpack.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("packing inner: %w", err)
	}

	innerSig, err := RsaSign(boxer.key, innerPacked)
	if err != nil {
		return nil, fmt.Errorf("signing inner: %w", err)
	}

	outer := outerBox{
		Inner:     innerPacked,
		Signature: innerSig,
		Sender:    fingerprint,
	}

	outerPacked, err := msgpack.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("packing outer: %w", err)
	}

	return outerPacked, nil
}

func (boxer boxMaker) DecodeUnverified(b64 string) (*Box, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	if len(data) > V0MaxSize {
		return nil, fmt.Errorf("data too big, is %d, max is %d", len(data), V0MaxSize)
	}

	return boxer.DecodeRawUnverified(data)
}

func (boxer boxMaker) DecodeRawUnverified(data []byte) (*Box, error) {
	var outer outerBox
	if err := msgpack.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("unmarshalling outer: %w", err)
	}

	return boxer.decodeInner(outer)
}

func (boxer boxMaker) Decode(b64 string) (*Box, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return boxer.DecodeRaw(data)
}

func (boxer boxMaker) DecodePngUnverified(r io.Reader) (*Box, error) {
	var data bytes.Buffer
	if err := FromPng(r, &data); err != nil {
		return nil, fmt.Errorf("decoding png: %w", err)
	}

	if data.Len() > V0MaxSize {
		return nil, errors.New("looks to be larger than max box size")
	}

	return boxer.DecodeRawUnverified(data.Bytes())
}

func (boxer boxMaker) DecodeRaw(data []byte) (*Box, error) {
	if len(data) > V0MaxSize {
		return nil, fmt.Errorf("data too big, is %d, max is %d", len(data), V0MaxSize)
	}

	var outer outerBox
	if err := msgpack.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("unmarshalling outer: %w", err)
	}

	if err := RsaVerify(boxer.counterparty, outer.Inner, outer.Signature); err != nil {
		return nil, fmt.Errorf("verifying outer: %w", err)
	}

	return boxer.decodeInner(outer)
}

func (boxer boxMaker) decodeInner(outer outerBox) (*Box, error) {
	if boxer.key == nil {
		return nil, errors.New("Can't decode without a key")
	}

	var inner Box
	if err := msgpack.Unmarshal(outer.Inner, &inner); err != nil {
		return nil, fmt.Errorf("unmarshalling inner: %w", err)
	}

	// Only decode if the inner has ciphertext. It's acceptable to have no ciphertext,
	// this is just a signature.
	if inner.Ciphertext != nil {
		aeskey, err := RsaDecrypt(boxer.key, inner.Key)
		if err != nil {
			return nil, fmt.Errorf("decrypting DEK: %w", err)
		}

		plaintext, err := AesDecrypt(aeskey, nil, inner.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypting data: %w", err)
		}

		inner.data = plaintext
	}

	inner.sender = outer.Sender

	return &inner, nil
}
