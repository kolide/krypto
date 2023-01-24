//go:build darwin
// +build darwin

package secureenclave

// this was heavily inspiried by https://github.com/facebookincubator/sks
// thank you!

/*
#cgo darwin LDFLAGS: -framework Foundation -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <secureenclave.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

type SecureEnclaveSigner struct {
	publicKey *ecdsa.PublicKey
}

// New verifies that the provided public key already exists in the secure enclave.
// Then returns a new Secure Enclave Keyer using the provided public key.
func New(publicKeySha1 []byte) (*SecureEnclaveSigner, error) {
	pubKey, err := findKey(publicKeySha1)
	if err != nil {
		return nil, fmt.Errorf("finding existing public key: %w", err)
	}

	s := &SecureEnclaveSigner{
		publicKey: pubKey,
	}

	return s, nil
}

func (s *SecureEnclaveSigner) Type() string {
	return "secure-enclave"
}

func (s *SecureEnclaveSigner) Public() crypto.PublicKey {
	return *s.publicKey
}

func (s *SecureEnclaveSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	lookupHash, err := publicKeyLookUpHash(s.publicKey)
	if err != nil {
		return nil, err
	}

	cData := C.CBytes(digest)
	defer C.free(cData)
	cDataSize := C.int(len(digest))

	cHash := C.CBytes(lookupHash)
	defer C.free(cHash)

	wrapper := C.wrapSign(cHash, cData, cDataSize)
	result, err := unwrap(wrapper)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CreateKey creates a new secure enclave key and returns the hash used to access it.
func CreateKey() ([]byte, error) {
	wrapper := C.wrapCreateKey()
	result, err := unwrap(wrapper)
	if err != nil {
		return nil, err
	}

	sha1 := sha1.New()
	if _, err := sha1.Write(result); err != nil {
		return nil, fmt.Errorf("hashing secure enclave create key result to sha1: %w", err)
	}
	return sha1.Sum(nil), nil
}

// unwrap a Wrapper struct to a Go byte slice
// Free the underlying bufs so caller won't have to deal with them
func unwrap(w *C.Wrapper) ([]byte, error) {
	if w == nil {
		return nil, errors.New("tried to unwrap empty response")
	}
	defer C.free(unsafe.Pointer(w))

	var res []byte
	var err error

	if w.error != nil {
		msg := C.GoString(w.error)
		err = errors.New(msg)
		C.free(unsafe.Pointer(w.error))
	}

	if w.buf != nil {
		res = C.GoBytes(unsafe.Pointer(w.buf), C.int(w.size))
		C.free(unsafe.Pointer(w.buf))
	}
	return res, err
}

// findKey finds a key in secure enclave by looking it up with the SHA1 hash of the public key
func findKey(publicKeySha1 []byte) (*ecdsa.PublicKey, error) {
	cHash := C.CBytes(publicKeySha1)
	defer C.free(cHash)

	wrapper := C.wrapFindKey(cHash)
	result, err := unwrap(wrapper)
	if err != nil {
		return nil, err
	}

	return rawToEcdsa(result), nil
}

func rawToEcdsa(raw []byte) *ecdsa.PublicKey {
	ecKey := new(ecdsa.PublicKey)
	ecKey.Curve = elliptic.P256()
	ecKey.X, ecKey.Y = elliptic.Unmarshal(ecKey.Curve, raw)
	return ecKey
}

func publicKeyLookUpHash(key *ecdsa.PublicKey) ([]byte, error) {
	if key.X == nil || key.Y == nil {
		return nil, errors.New("public key has nil XY coordinates")
	}

	keyBytes := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	hash := sha1.New()
	hash.Write(keyBytes)
	return hash.Sum(nil), nil
}
