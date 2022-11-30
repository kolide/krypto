package krypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpmEncoder struct {
	publicSigningKey    *rsa.PublicKey
	publicEncryptionKey *rsa.PublicKey
	externalTpm         io.ReadWriteCloser
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

// Decrypt decrypts the provided input with a generated key.
// The keys are derived deterministically from the TPM built-in and protected seed.
// This means the keys will always be the same as long as the TPM is not reset.
// Use PublicEncryptionKey() to get the public key
func (t *tpmEncoder) Decrypt(input []byte) ([]byte, error) {
	tpm, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer t.closeTpm(tpm)

	handle, _, err := encryptionKey(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tpm, handle) //nolint:errcheck

	return tpm2.RSADecrypt(tpm, handle, "", input, &tpm2.AsymScheme{Alg: tpm2.AlgOAEP, Hash: tpm2.AlgSHA1}, "")
}

// PublicEncryptionKey returns the public key of the key used for signing.
// The key is derived deterministically from the TPM built-in and protected seed.
// This means the keys will always be the same as long as the TPM is not reset.
func (t *tpmEncoder) PublicEncryptionKey() (*rsa.PublicKey, error) {
	if t.publicEncryptionKey != nil {
		return t.publicEncryptionKey, nil
	}

	tpm, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	defer t.closeTpm(tpm)

	handle, publicKey, err := encryptionKey(tpm)
	if err != nil {
		return nil, fmt.Errorf("creating encryption key: %w", err)
	}
	defer tpm2.FlushContext(tpm, handle) //nolint:errcheck

	t.publicEncryptionKey = publicKey.(*rsa.PublicKey)
	return t.publicEncryptionKey, nil
}

func (t *tpmEncoder) signingKeyTemplate() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		// can add tpm2.FlagRestricted to the attributes to force the TPM to do the hashing as well, but this severely limits the size
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
	tpm, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer t.closeTpm(tpm)

	signingKey, err := client.NewKey(tpm, tpm2.HandleEndorsement, t.signingKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("opening signing key: %w", err)
	}
	defer signingKey.Close()

	hash := sha256.New()
	if _, err := hash.Write(input); err != nil {
		return nil, fmt.Errorf("hashing input: %w", err)
	}

	return signingKey.SignData(input)
}

// PublicSigningKey returns the public key of the key used for signing.
// The key is derived deterministically from the TPM built-in and protected seed.
// This means the keys will always be the same as long as the TPM is not reset.
func (t *tpmEncoder) PublicSigningKey() (*rsa.PublicKey, error) {
	if t.publicSigningKey != nil {
		return t.publicSigningKey, nil
	}

	tpm, err := t.openTpm()
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	defer t.closeTpm(tpm)

	signingKey, err := client.NewKey(tpm, tpm2.HandleEndorsement, t.signingKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("creating signing key: %w", err)
	}
	defer signingKey.Close()

	t.publicSigningKey = signingKey.PublicKey().(*rsa.PublicKey)
	return t.publicSigningKey, nil
}

func (t *tpmEncoder) closeTpm(tpm io.ReadWriteCloser) {
	if t.externalTpm != nil {
		return
	}

	tpm.Close()
}