package krypto

import (
	"crypto/rsa"
	"os"
	"path"
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

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()
		require.Error(t, RsaVerify(nil, message, sig))
	})

	t.Run("nil message", func(t *testing.T) {
		t.Parallel()
		require.Error(t, RsaVerify(pub, nil, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		t.Parallel()
		require.Error(t, RsaVerify(pub, message, nil))
	})
}

func TestNilRsaEncrypt(t *testing.T) {
	t.Parallel()

	_, err := RsaEncrypt(nil, []byte("hello"))
	require.Error(t, err)
}

func TestNilRsaDecrypt(t *testing.T) {
	t.Parallel()
	var err error

	_, err = RsaDecrypt(nil, mkrand(t, 32))
	require.Error(t, err)

	key, err := RsaRandomKey()
	require.NoError(t, err)

	_, err = RsaDecrypt(key, nil)
	require.Error(t, err)
}

func TestRsaSign(t *testing.T) {
	t.Parallel()

	_, err := RsaSign(nil, []byte("hello"))
	require.Error(t, err)
}

func TestRsaFingerprint(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		infile   string
		expected string
	}{
		{
			infile:   path.Join("test-data", "public.pem"),
			expected: "80:61:16:6c:86:e8:9f:a2:91:49:b4:75:f8:46:1a:ae:9d:a6:72:e9:dd:4a:c4:f5:b3:07:d1:3a:99:ba:d7:71",
		},
		{
			infile:   path.Join("test-data", "private.pem"),
			expected: "80:61:16:6c:86:e8:9f:a2:91:49:b4:75:f8:46:1a:ae:9d:a6:72:e9:dd:4a:c4:f5:b3:07:d1:3a:99:ba:d7:71",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.infile, func(t *testing.T) {
			t.Parallel()

			contents, err := os.ReadFile(tt.infile)
			require.NoError(t, err)

			key, err := KeyFromPem(contents)
			require.NoError(t, err)

			actual, err := RsaFingerprint(key)
			require.NoError(t, err)

			require.Equal(t, tt.expected, actual)

		})
	}
}
