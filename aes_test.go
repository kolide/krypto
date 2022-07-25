package krypto

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAesRandomRoundTrips(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in       []byte
		authdata []byte
	}{
		{in: []byte("a")},
		{in: mkrand(t, 30)},
		{in: mkrand(t, 31)},
		{in: mkrand(t, 32)},
		{in: mkrand(t, 33)},
		{in: mkrand(t, 254)},
		{in: mkrand(t, 255)},
		{in: mkrand(t, 256)},
		{in: mkrand(t, 257)},

		{in: mkrand(t, 30), authdata: mkrand(t, 30)},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("size %d", len(tt.in)), func(t *testing.T) {
			t.Parallel()
			key := mkrand(t, 32)

			ciphertext, err := aesEncrypt(key, tt.authdata, tt.in)
			require.NoError(t, err)
			require.NotEqual(t, tt.in, ciphertext)

			decrypted, err := aesDecrypt(key, tt.authdata, ciphertext)
			require.NoError(t, err)
			require.Equal(t, tt.in, decrypted)

			t.Run("broken ciphertext", func(t *testing.T) {
				t.Parallel()
				broken, err := aesDecrypt(key, tt.authdata, ciphertext[2:])
				require.Error(t, err)
				require.Nil(t, broken)
			})

			t.Run("broken key", func(t *testing.T) {
				t.Parallel()
				broken, err := aesDecrypt(key[2:], tt.authdata, ciphertext)
				require.Error(t, err)
				require.Nil(t, broken)

			})

		})
	}

}

func TestAesDecryptCompatibility(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		key        string
		authdata   string
		ciphertext string
		plaintext  string
	}{
		{
			key:        "ogUA4ZhnF/2w7A/L4NMvdPJ3LudylBUjz//qmBIkd20=",
			ciphertext: "sZsYk5c0gag0Muad3ZTErEtV1r+yim0OSmgGQxsok2dAUjGZ1SUWXMmk51+Tb1prg4x+U100hxkhPZoTa2IiX96TTp9E",
			plaintext:  "Sounds like we need a ratchet, stray cat.",
		},
		{
			key:        "pkhRvfaCi5Z2H4/FSv+FTA1c5oII226F1FjwTeRh0i0=",
			ciphertext: "QdpCbU+FJpOm2ejy91/P2p5vU9AvZ+dGTAr/1fg=",
			plaintext:  "a",
		},
		{
			key:        "1YrTa47323UVHPIZlUNokGc/cU89/KI7DYB/Nu1axgY=",
			authdata:   "aGVsbG8=",
			ciphertext: "ZVBAGN0omjQfs2HBOgAUwljag8kRDdyrHOK/DwJreU4HyetHSNiG",
			plaintext:  "Hello World",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			key := base64Decode(t, tt.key)
			authdata := base64Decode(t, tt.authdata)
			ciphertext := base64Decode(t, tt.ciphertext)

			actual, err := aesDecrypt(key, authdata, ciphertext)
			require.NoError(t, err)
			require.Equal(t, tt.plaintext, string(actual))

			t.Run("broken ciphertext", func(t *testing.T) {
				t.Parallel()
				broken, err := aesDecrypt(key, authdata, ciphertext[2:])
				require.Error(t, err)
				require.Nil(t, broken)
			})

			t.Run("broken key", func(t *testing.T) {
				t.Parallel()
				broken, err := aesDecrypt(key[2:], authdata, ciphertext)
				require.Error(t, err)
				require.Nil(t, broken)

			})

		})
	}
}

func mkrand(t *testing.T, size int) []byte {
	r := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, r)
	require.NoError(t, err)
	return r
}

func base64Decode(t *testing.T, raw string) []byte {
	d, err := base64.StdEncoding.DecodeString(raw)
	require.NoError(t, err)
	return d
}
