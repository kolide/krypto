package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type TpmSignerOption func(*TpmSigner)

// WithExternalTpm lets the caller provide the tpm hardware interface to use instead of letting the keyer auto discover.
// This is useful for testing in a CI environment where you may not have access to a TPM chip.
// The caller is responsible for closing the external tpm.
func WithExternalTpm(externalTpm io.ReadWriteCloser) TpmSignerOption {
	return func(t *TpmSigner) {
		t.externalTpm = externalTpm
	}
}

type TpmSigner struct {
	externalTpm io.ReadWriteCloser
	tpmLock     sync.Mutex
	publicKey   ecdsa.PublicKey
	privateBlob []byte
	publicBlob  []byte
}

func New(private []byte, public []byte, opts ...TpmSignerOption) (*TpmSigner, error) {
	tpmKeyer := &TpmSigner{
		privateBlob: private,
		publicBlob:  public,
	}

	for _, opt := range opts {
		opt(tpmKeyer)
	}

	tpm, err := tpmKeyer.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	// nolint: errcheck
	defer tpmKeyer.closeInternalTpm(tpm)

	parentHandle, err := parentHandle(tpm)
	if err != nil {
		return nil, fmt.Errorf("loading parent handle: %w", err)
	}
	// nolint: errcheck
	defer tpm2.FlushContext(tpm, parentHandle)

	signerHandle, publicKey, err := loadSignerHandle(tpm, parentHandle, public, private)
	if err != nil {
		return nil, fmt.Errorf("loading signer handle: %w", err)
	}
	// nolint: errcheck
	defer tpm2.FlushContext(tpm, signerHandle)

	tpmKeyer.publicKey = *publicKey

	return tpmKeyer, nil
}

func CreateKey(opts ...TpmSignerOption) (private []byte, public []byte, err error) {
	tpmSigner := TpmSigner{}
	for _, opt := range opts {
		opt(&tpmSigner)
	}

	tpm, err := tpmSigner.openTpm()
	if err != nil {
		return nil, nil, fmt.Errorf("opening tpm: %w", err)
	}
	//nolint: errcheck
	defer tpmSigner.closeInternalTpm(tpm)

	primaryHandle, err := parentHandle(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("creating primary key: %w", err)
	}
	//nolint: errcheck
	defer tpm2.FlushContext(tpm, primaryHandle)

	private, public, _, _, _, err = tpm2.CreateKey(tpm, primaryHandle, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	})

	if err != nil {
		return nil, nil, fmt.Errorf("creating key: %w", err)
	}

	return private, public, nil
}

func (s *TpmSigner) Type() string {
	if s.externalTpm != nil {
		return "tpm-external"
	}

	return "tpm"
}

func (s *TpmSigner) Public() crypto.PublicKey {
	return &s.publicKey
}

func (s *TpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	s.tpmLock.Lock()
	defer s.tpmLock.Unlock()

	tpm, err := s.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	//nolint: errcheck
	defer s.closeInternalTpm(tpm)

	parentHandle, err := parentHandle(tpm)
	if err != nil {
		return nil, fmt.Errorf("getting parent handle: %w", err)
	}
	//nolint: errcheck
	defer tpm2.FlushContext(tpm, parentHandle)

	signingHandle, _, err := loadSignerHandle(tpm, parentHandle, s.publicBlob, s.privateBlob)
	if err != nil {
		return nil, fmt.Errorf("loading signer handle: %w", err)
	}
	//nolint: errcheck
	defer tpm2.FlushContext(tpm, signingHandle)

	sig, err := tpm2.Sign(tpm, signingHandle, "", digest, nil, &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	})

	if err != nil {
		return nil, fmt.Errorf("signing digest: %w", err)
	}

	return encodeAns1(*sig)
}

func encodeAns1(sig tpm2.Signature) ([]byte, error) {
	bigInts := struct {
		R, S *big.Int
	}{
		R: sig.ECC.R,
		S: sig.ECC.S,
	}

	return asn1.Marshal(bigInts)
}

func parentHandle(tpm io.ReadWriteCloser) (tpmutil.Handle, error) {
	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	})

	return parentHandle, err
}

func loadSignerHandle(tpm io.ReadWriter, parentHandle tpmutil.Handle, publicBlob []byte, privateBlob []byte) (tpmutil.Handle, *ecdsa.PublicKey, error) {
	handle, _, err := tpm2.Load(tpm, parentHandle, "", publicBlob, privateBlob)
	if err != nil {
		return 0, nil, fmt.Errorf("loading signer handle: %w", err)
	}

	tpm2Public, err := tpm2.DecodePublic(publicBlob)
	if err != nil {
		return 0, nil, fmt.Errorf("decoding public bytes: %w", err)
	}

	cryptoPub, err := tpm2Public.Key()
	if err != nil {
		return 0, nil, fmt.Errorf("decoding public key: %w", err)
	}

	ecdsaPubKey, ok := cryptoPub.(*ecdsa.PublicKey)
	if !ok {
		return 0, nil, fmt.Errorf("signer pubkey in unexpected format (expected ECDSA, got %T)", cryptoPub)
	}

	return handle, ecdsaPubKey, nil
}

func (t *TpmSigner) closeInternalTpm(tpm io.ReadWriteCloser) error {
	if t.externalTpm != nil {
		return nil
	}

	return tpm.Close()
}

func (t *TpmSigner) openTpm() (io.ReadWriteCloser, error) {
	if t.externalTpm != nil {
		return t.externalTpm, nil
	}

	if runtime.GOOS == "darwin" {
		return nil, errors.New("external TPM required for darwin, but was nil")
	}

	return tpm2.OpenTPM()
}
