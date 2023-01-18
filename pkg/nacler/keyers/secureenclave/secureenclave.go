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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"unsafe"
)

type SecureEnclaveKeyer struct {
	publicKey *ecdsa.PublicKey
}

// New verifies that the provided public key already exists in the secure enclave.
// Then returns a new Secure Enclave Keyer using the provided public key.
func New(publicKey ecdsa.PublicKey) (*SecureEnclaveKeyer, error) {
	se := &SecureEnclaveKeyer{
		publicKey: &publicKey,
	}

	_, err := findKey(*se.publicKey)
	if err != nil {
		return nil, fmt.Errorf("finding existing public key: %w", err)
	}

	return se, nil
}

func (s *SecureEnclaveKeyer) PublicKey() (ecdsa.PublicKey, error) {
	return *s.publicKey, nil
}

func (s *SecureEnclaveKeyer) SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error) {
	if counterParty.X == nil || counterParty.Y == nil {
		return [32]byte{}, errors.New("counterParty public key has nil XY coordinates")
	}

	lookupHash, err := publicKeyLookUpHash(s.publicKey)
	if err != nil {
		return [32]byte{}, err
	}

	counterPartyMarshalled := elliptic.Marshal(counterParty.Curve, counterParty.X, counterParty.Y)
	cCounterParty := C.CBytes(counterPartyMarshalled)
	cCounterPartySize := C.int(len(counterPartyMarshalled))

	cHash := C.CBytes(lookupHash)
	defer C.free(cHash)

	wrapper := C.wrapECDH(cHash, cCounterParty, cCounterPartySize)
	result, err := unwrap(wrapper)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(result), err
}

// CreateKey creates a new secure enclave key and returns it.
func CreateKey() (*ecdsa.PublicKey, error) {
	wrapper := C.wrapCreateKey()
	result, err := unwrap(wrapper)
	if err != nil {
		return nil, err
	}

	return rawToEcdsa(result), nil
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
func findKey(publicKey ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	lookupHash, err := publicKeyLookUpHash(&publicKey)
	if err != nil {
		return nil, err
	}

	cHash := C.CBytes(lookupHash)
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
