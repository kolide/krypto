package krypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/kolide/kit/ulid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(ulid.New())

	ciphertext, err := rsaEncrypt(pub, message)
	require.NoError(t, err)

	require.NotEqual(t, message, ciphertext)

	decrypted, err := rsaDecrypt(key, ciphertext)
	require.NoError(t, err)

	require.Equal(t, message, decrypted)

	// Break Stuff
	t.Run("broken ciphertext", func(t *testing.T) {
		t.Parallel()
		cantDecrypt, err := rsaDecrypt(key, ciphertext[1:])
		assert.Error(t, err)
		assert.Nil(t, cantDecrypt)
	})
}

func TestSigning(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(ulid.New())

	sig, err := rsaSign(key, message)
	require.NoError(t, err)

	require.NoError(t, rsaVerify(pub, message, sig))

	// Break stuff
	t.Run("broken message", func(t *testing.T) {
		t.Parallel()
		require.Error(t, rsaVerify(pub, message[2:], sig))
	})
	t.Run("broken signature", func(t *testing.T) {
		t.Parallel()
		require.Error(t, rsaVerify(pub, message, sig[2:]))
	})
}
