package krypto

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	t.Parallel()

	key, err := RsaRandomKey()
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(randomString(t, 64))

	ciphertext, err := RsaEncrypt(pub, message)
	require.NoError(t, err)

	require.NotEqual(t, message, ciphertext)

	decrypted, err := RsaDecrypt(key, ciphertext)
	require.NoError(t, err)

	require.Equal(t, message, decrypted)

	// Break Stuff
	t.Run("broken ciphertext", func(t *testing.T) {
		t.Parallel()
		cantDecrypt, err := RsaDecrypt(key, ciphertext[1:])
		assert.Error(t, err)
		assert.Nil(t, cantDecrypt)
	})
}

func TestSigning(t *testing.T) {
	t.Parallel()

	key, err := RsaRandomKey()
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(randomString(t, 64))

	sig, err := RsaSign(key, message)
	require.NoError(t, err)

	require.NoError(t, RsaVerify(pub, message, sig))

	// Break stuff
	t.Run("broken message", func(t *testing.T) {
		t.Parallel()
		require.Error(t, RsaVerify(pub, message[2:], sig))
	})
	t.Run("broken signature", func(t *testing.T) {
		t.Parallel()
		require.Error(t, RsaVerify(pub, message, sig[2:]))
	})
}
