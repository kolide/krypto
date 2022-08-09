package krypto

import (
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/png"
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

type innerBox struct {
	Version    int    `msgpack:"version"`
	Timestamp  int64  `msgpack:"timestamp"`
	Key        []byte `msgpack:"key"`
	Ciphertext []byte `msgpack:"ciphertext"`
	RequestId  string `msgpack:"requestid"`
	ResponseTo string `msgpack:"responseto"`
}

type boxMaker struct {
	key          *rsa.PrivateKey
	counterparty *rsa.PublicKey
	baseImg      image.Image
}

//go:embed 1x1.png
var onexonePng []byte

const maxBoxSize = 4 * 1024 * 1024

func NewBoxer(key *rsa.PrivateKey, counterparty *rsa.PublicKey) boxMaker {
	/*
		// Set the base PNG. This is a panic, because it's only dealing with constants.
		baseImg, err := png.Decode(onexonePNG())
		if err != nil {
			panic(err)
		}

		// TODO metadata
	*/

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

	w.Write(onexonePng)
	w.Write(raw)
	return nil
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

	inner := innerBox{
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

	fingerprint, err := RsaFingerprint(boxer.key)
	if err != nil {
		return nil, fmt.Errorf("unable to fingerprint: %w", err)
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

func (boxer boxMaker) DecodeUnverified(b64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return boxer.DecodeRawUnverified(data)
}

func (boxer boxMaker) DecodeRawUnverified(data []byte) ([]byte, error) {
	var outer outerBox
	if err := msgpack.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("unmarshalling outer: %w", err)
	}

	return boxer.decodeInner(outer.Inner)
}

func (boxer boxMaker) Decode(b64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return boxer.DecodeRaw(data)
}

func (boxer boxMaker) DecodePngUnverified(r io.Reader) ([]byte, error) {
	// Instead of manually looking for `IEND`, we let the go png parser wind the io.Reader for us.
	_, err := png.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("png splitting: %w", err)
	}

	buf := make([]byte, maxBoxSize)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("unable to read data: %w", err)
	}
	if n == maxBoxSize {
		return nil, errors.New("looks to be larger than max box size")
	}

	return boxer.DecodeRawUnverified(buf[:n])
}

func (boxer boxMaker) DecodeRaw(data []byte) ([]byte, error) {
	var outer outerBox
	if err := msgpack.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("unmarshalling outer: %w", err)
	}

	if err := RsaVerify(boxer.counterparty, outer.Inner, outer.Signature); err != nil {
		return nil, fmt.Errorf("verifying outer: %w", err)
	}

	return boxer.decodeInner(outer.Inner)
}

func (boxer boxMaker) decodeInner(data []byte) ([]byte, error) {
	if boxer.key == nil {
		return nil, errors.New("Can't decode without a key")
	}

	var inner innerBox
	if err := msgpack.Unmarshal(data, &inner); err != nil {
		return nil, fmt.Errorf("unmarshalling inner: %w", err)
	}

	aeskey, err := RsaDecrypt(boxer.key, inner.Key)
	if err != nil {
		return nil, fmt.Errorf("decrypting DEK: %w", err)
	}

	plaintext, err := AesDecrypt(aeskey, nil, inner.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}

	return plaintext, err
}
