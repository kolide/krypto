package krypto

import (
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
	}
}
