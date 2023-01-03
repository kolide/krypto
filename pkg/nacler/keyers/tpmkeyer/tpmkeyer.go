package tpmkeyer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const tpmKeyBitCount = 2048

type TpmKeyerOption func(*TpmKeyer)

// WithExternalTpm lets the caller provide a tpm to use. This is useful for testing.
// The caller is responsible for closing the external tpm.
func WithExternalTpm(externalTpm io.ReadWriteCloser) TpmKeyerOption {
	return func(t *TpmKeyer) {
		t.externalTpm = externalTpm
	}
}

type TpmKeyer struct {
	externalTpm io.ReadWriteCloser
	tpmLock     sync.Mutex
	publicKey   *ecdsa.PublicKey
}

func New(opts ...TpmKeyerOption) *TpmKeyer {
	tpmKeyer := &TpmKeyer{}
	for _, opt := range opts {
		opt(tpmKeyer)
	}
	return tpmKeyer
}

func (t *TpmKeyer) SharedKey(counterParty ecdsa.PublicKey) ([32]byte, error) {
	t.tpmLock.Lock()
	defer t.tpmLock.Unlock()

	tpm, err := t.openTpm()
	if err != nil {
		return [32]byte{}, fmt.Errorf("opening tpm: %w", err)
	}
	defer t.closeInternalTpm(tpm)

	handle, _, err := createKey(tpm)
	if err != nil {
		return [32]byte{}, fmt.Errorf("creating tpm key: %w", err)
	}
	defer tpm2.FlushContext(tpm, handle)

	shared, err := tpm2.ECDHZGen(tpm, handle, "", tpm2.ECPoint{
		XRaw: counterParty.X.Bytes(),
		YRaw: counterParty.Y.Bytes(),
	})

	if err != nil {
		return [32]byte{}, fmt.Errorf("generating shared key with tpm: %w", err)
	}

	return sha256.Sum256(shared.X().Bytes()), nil
}

func (t *TpmKeyer) PublicKey() (ecdsa.PublicKey, error) {
	t.tpmLock.Lock()
	defer t.tpmLock.Unlock()

	if t.publicKey != nil {
		return *t.publicKey, nil
	}

	tpm, err := t.openTpm()
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("opening tpm: %w", err)
	}
	defer t.closeInternalTpm(tpm)

	handle, pub, err := createKey(tpm)
	if err != nil {
		return ecdsa.PublicKey{}, fmt.Errorf("creating key: %w", err)
	}
	defer tpm2.FlushContext(tpm, handle)

	t.publicKey = pub.(*ecdsa.PublicKey)
	return *t.publicKey, nil
}

func createKey(tpm io.ReadWriteCloser) (tpmutil.Handle, crypto.PublicKey, error) {
	return tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	})
}

func (t *TpmKeyer) closeInternalTpm(tpm io.ReadWriteCloser) error {
	if t.externalTpm != nil {
		return nil
	}

	return tpm.Close()
}