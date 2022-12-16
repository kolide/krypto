package rsafunc

import (
	"crypto/rsa"
	"os"
	"path"
	"testing"

	"github.com/kolide/krypto/pkg/testfunc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	t.Parallel()

	key, err := RandomKey()
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(testfunc.RandomString(t, 64))

	ciphertext, err := Encrypt(pub, message)
	require.NoError(t, err)

	require.NotEqual(t, message, ciphertext)

	decrypted, err := Decrypt(key, ciphertext)
	require.NoError(t, err)

	require.Equal(t, message, decrypted)

	// Break Stuff
	t.Run("broken ciphertext", func(t *testing.T) {
		t.Parallel()
		cantDecrypt, err := Decrypt(key, ciphertext[1:])
		assert.Error(t, err)
		assert.Nil(t, cantDecrypt)
	})
}

func TestSigning(t *testing.T) {
	t.Parallel()

	key, err := RandomKey()
	require.NoError(t, err)
	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	message := []byte(testfunc.RandomString(t, 64))

	sig, err := Sign(key, message)
	require.NoError(t, err)

	require.NoError(t, Verify(pub, message, sig))

	// Break stuff
	t.Run("broken message", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Verify(pub, message[2:], sig))
	})

	t.Run("broken signature", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Verify(pub, message, sig[2:]))
	})

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Verify(nil, message, sig))
	})

	t.Run("nil message", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Verify(pub, nil, sig))
	})

	t.Run("nil signature", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Verify(pub, message, nil))
	})
}

func TestNilRsaEncrypt(t *testing.T) {
	t.Parallel()

	_, err := Encrypt(nil, []byte("hello"))
	require.Error(t, err)
}

func TestNilRsaDecrypt(t *testing.T) {
	t.Parallel()
	var err error

	_, err = Decrypt(nil, testfunc.Mkrand(t, 32))
	require.Error(t, err)

	key, err := RandomKey()
	require.NoError(t, err)

	_, err = Decrypt(key, nil)
	require.Error(t, err)
}

func TestRsaSign(t *testing.T) {
	t.Parallel()

	_, err := Sign(nil, []byte("hello"))
	require.Error(t, err)
}

func TestRsaFingerprint(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		infile   string
		expected string
	}{
		{
			infile:   path.Join("..", "..", "test-data", "public.pem"),
			expected: "80:61:16:6c:86:e8:9f:a2:91:49:b4:75:f8:46:1a:ae:9d:a6:72:e9:dd:4a:c4:f5:b3:07:d1:3a:99:ba:d7:71",
		},
		{
			infile:   path.Join("..", "..", "test-data", "private.pem"),
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

			actual, err := Fingerprint(key)
			require.NoError(t, err)

			require.Equal(t, tt.expected, actual)

		})
	}
}
