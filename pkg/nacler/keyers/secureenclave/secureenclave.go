//go:build darwin
// +build darwin

package secureenclave

// this was heavily inspiried by https://github.com/facebookincubator/sks
// thank you!

/*
#cgo darwin LDFLAGS: -framework Foundation -framework Security -framework CoreFoundation

#include <stdlib.h>
#include <secureenclave.h>

typedef struct wrapper {
	unsigned char *buf;
	int status;
	size_t size;
	char *error;
} Wrapper;

Wrapper *wrapCreateKey() {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = createKey(&res->buf, &res->error);
	return res;
}

Wrapper *wrapFindKey(void *hash) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = findKey((unsigned char *)hash, &res->buf, &res->error);
	return res;
}

Wrapper *wrapECDH(void *hash, void *counterParty, int counterPartySize) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = ecdh((unsigned char *)hash, (unsigned char *)counterParty, counterPartySize, &res->buf, &res->error);
	return res;
}
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

type SecureEnclaveKeyerOption func(*SecureEnclaveKeyer)

func WithExistingKey(publicKey ecdsa.PublicKey) SecureEnclaveKeyerOption {
	return func(s *SecureEnclaveKeyer) {
		s.publicKey = &publicKey
	}
}

type SecureEnclaveKeyer struct {
	publicKey *ecdsa.PublicKey
}

func New(opts ...SecureEnclaveKeyerOption) (*SecureEnclaveKeyer, error) {
	se := &SecureEnclaveKeyer{}

	for _, opt := range opts {
		opt(se)
	}

	// if the call provided a public key, make sure we can find it in secure enclave
	if se.publicKey != nil {
		_, err := findKey(*se.publicKey)
		if err != nil {
			return nil, fmt.Errorf("finding existing public key: %w", err)
		}

		return se, nil
	}

	publicKey, err := createKey()
	if err != nil {
		return nil, fmt.Errorf("creating new public key: %w", err)
	}

	se.publicKey = publicKey
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

	marshalled := elliptic.Marshal(counterParty.Curve, counterParty.X, counterParty.Y)
	cCounterParty := C.CBytes(marshalled)
	cCounterPartySize := C.int(len(marshalled))

	cHash := C.CBytes(lookupHash)
	defer C.free(cHash)

	wrapper := C.wrapECDH(cHash, cCounterParty, cCounterPartySize)
	result, err := unwrap(wrapper)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(result), err
}

// unwrap a Wrapper struct to a Go byte slice
// Free the underlying bufs so caller won't have to deal with them
func unwrap(w *C.Wrapper) (res []byte, err error) {
	defer C.free(unsafe.Pointer(w))
	if w == nil {
		return nil, errors.New("tried to unwrap empty response")
	}

	if w.error != nil {
		msg := C.GoString(w.error)
		err = errors.New(msg)
		C.free(unsafe.Pointer(w.error))
	}

	if w.buf != nil {
		res = C.GoBytes(unsafe.Pointer(w.buf), C.int(w.size))
		C.free(unsafe.Pointer(w.buf))
	}
	return
}

func createKey() (*ecdsa.PublicKey, error) {
	wrapper := C.wrapCreateKey()
	result, err := unwrap(wrapper)
	if err != nil {
		return nil, err
	}

	return rawToEcdsa(result), nil
}

// findKey finds a key in secure enclave with a specific label, tag, & SHA1 hash of the public key
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
