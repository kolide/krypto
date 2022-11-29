package krypto

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	CryptoHash  = crypto.SHA256
	signingAlgo = tpm2.AlgRSAPSS
)

type tpmEncoder struct {
	publicSigningKey    *rsa.PublicKey
	publicEncryptionKey *rsa.PublicKey
	openTpm             func() (io.ReadWriteCloser, error)
}

func newTpmEncoder() *tpmEncoder {
	return &tpmEncoder{
		openTpm: tpm2.OpenTPM,
	}
}

func encryptionKey(tpm io.ReadWriteCloser) (tpmutil.Handle, crypto.PublicKey, error) {
	return tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: 2048,
		},
	})
}

func (t *tpmEncoder) Decrypt(input []byte) ([]byte, error) {
	rwc, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	handle, _, err := encryptionKey(rwc)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rwc, handle)

	return tpm2.RSADecrypt(rwc, handle, "", input, &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA1}, "")
}

func (t *tpmEncoder) PublicEncryptionKey() *rsa.PublicKey {
	if t.publicEncryptionKey != nil {
		return t.publicEncryptionKey
	}

	rwc, err := t.openTpm()
	if err != nil {
		return nil
	}
	defer rwc.Close()

	handle, publicKey, err := encryptionKey(rwc)
	if err != nil {
		return nil
	}
	defer tpm2.FlushContext(rwc, handle)

	t.publicEncryptionKey = publicKey.(*rsa.PublicKey)
	return t.publicEncryptionKey
}

func (t *tpmEncoder) signingKeyTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		// can add tpm2.FlagRestricted to the attributes to force the TPM to do the hashing as well, but this severly limits the size
		// of the datat that can be hashed
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

// Sign signs the provided input with a generated key.
// The keys are derived deterministically from the TPM built-in and protected seed.
// This means the keys will always be the same as long as the TPM is not reset.
// Use PublicSigningKey() to get the public key
func (t *tpmEncoder) Sign(input []byte) ([]byte, error) {
	rwc, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	signingKey, err := client.NewKey(rwc, tpm2.HandleEndorsement, t.signingKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("opening signing key: %w", err)
	}
	defer signingKey.Close()

	hash := CryptoHash.New()
	if _, err := hash.Write(input); err != nil {
		return nil, fmt.Errorf("hashing input: %w", err)
	}

	return signingKey.SignData(input)
}

// PublicSigningKey returns the public key of the key used for signing.
// The key is derived deterministically from the TPM built-in and protected seed.
// This means the keys will always be the same as long as the TPM is not reset.
func (t *tpmEncoder) PublicSigningKey() *rsa.PublicKey {
	if t.publicSigningKey != nil {
		return t.publicSigningKey
	}

	rwc, err := t.openTpm()
	if err != nil {
		return nil
	}
	defer rwc.Close()

	signingKey, err := client.NewKey(rwc, tpm2.HandleEndorsement, t.signingKeyTemplate())
	if err != nil {
		return nil
	}
	defer signingKey.Close()

	t.publicSigningKey = signingKey.PublicKey().(*rsa.PublicKey)
	return t.publicSigningKey
}
