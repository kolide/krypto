package krypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/kolide/kit/ulid"
	"github.com/stretchr/testify/require"
)

func TestBoxRandomRoundTrips(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in []byte
	}{
		{in: []byte("a")},
		{in: mkrand(t, 32)},
		{in: mkrand(t, 256)},
		{in: mkrand(t, 2048)},
		{in: mkrand(t, 4096)},
		{in: []byte(randomString(t, 4096))},
	}

	aliceKey, err := RsaRandomKey()
	require.NoError(t, err)

	bobKey, err := RsaRandomKey()
	require.NoError(t, err)

	malloryKey, err := RsaRandomKey()
	require.NoError(t, err)

	aliceBoxer := NewBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey))
	bobBoxer := NewBoxer(bobKey, aliceKey.Public().(*rsa.PublicKey))
	bareBobBoxer := NewBoxer(bobKey, nil)
	malloryBoxer := NewBoxer(malloryKey, aliceKey.Public().(*rsa.PublicKey))
	bareMalloryBoxer := NewBoxer(malloryKey, nil)

	var testFuncs = []struct {
		name      string
		fn        func(string) ([]byte, error)
		expectErr bool
	}{
		{name: "bob can decode", fn: bobBoxer.Decode},
		{name: "bob can decode unverified", fn: bobBoxer.DecodeUnverified},
		{name: "bare bob can decode unverified", fn: bareBobBoxer.DecodeUnverified},

		{name: "mallory cannot decode", fn: malloryBoxer.Decode, expectErr: true},
		{name: "mallory cannot decode unverified", fn: malloryBoxer.DecodeUnverified, expectErr: true},
		{name: "bare mallory cannot decode", fn: bareMalloryBoxer.Decode, expectErr: true},
		{name: "bare mallory cannot decode unverified", fn: bareMalloryBoxer.DecodeUnverified, expectErr: true},
		{name: "bare bob cannot verify and decode", fn: bareBobBoxer.Decode, expectErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("size %d", len(tt.in)), func(t *testing.T) {

			t.Run("roundtrips", func(t *testing.T) {
				t.Parallel()

				responseTo := ulid.New()

				ciphertext, err := aliceBoxer.Encode(responseTo, tt.in)
				require.NoError(t, err)
				require.NotContains(t, ciphertext, tt.in)

				for _, tf := range testFuncs {
					tf := tf
					t.Run(tf.name, func(t *testing.T) {
						t.Parallel()
						if tf.expectErr {
							plaintext, err := tf.fn(ciphertext)
							require.Error(t, err)
							require.Empty(t, plaintext)
						} else {
							plaintext, err := tf.fn(ciphertext)
							require.NoError(t, err)
							require.Equal(t, tt.in, plaintext, "decoded matches")
						}
					})
				}

			})

			t.Run("png", func(t *testing.T) {
				t.Parallel()
				responseTo := ulid.New()

				var buf bytes.Buffer
				require.NoError(t, aliceBoxer.EncodePng(responseTo, tt.in, &buf))

				plaintext, err := bobBoxer.DecodePngUnverified(&buf)
				require.NoError(t, err)

				require.Equal(t, tt.in, plaintext, "decoded matches")
			})
		})
	}
}

func TestNilNoPanic(t *testing.T) {
	t.Parallel()

	aliceKey, err := RsaRandomKey()
	require.NoError(t, err)

	bobKey, err := RsaRandomKey()
	require.NoError(t, err)

	workingBoxer := NewBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey))
	ciphertext, err := workingBoxer.EncodeRaw(ulid.New(), mkrand(t, 32))
	require.NoError(t, err)

	_, err = workingBoxer.EncodeRaw("", nil)
	require.NoError(t, err)

	var tests = []struct {
		name  string
		boxer boxMaker
	}{
		{name: "all nil", boxer: NewBoxer(nil, nil)},
		{name: "nil counterparty", boxer: NewBoxer(aliceKey, nil)},
		{name: "nil me", boxer: NewBoxer(nil, bobKey.Public().(*rsa.PublicKey))},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error

			_, err = tt.boxer.EncodeRaw("", []byte("hello"))
			require.Error(t, err)

			_, err = tt.boxer.EncodeRaw("", nil)
			require.Error(t, err)

			_, err = tt.boxer.DecodeRaw(ciphertext)
			require.Error(t, err)

			_, err = tt.boxer.DecodeRaw(nil)
			require.Error(t, err)

		})
	}

}
