package krypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/kolide/kit/ulid"
	"github.com/kolide/krypto/pkg/keyencoder"
	"github.com/kolide/krypto/pkg/rsafunc"
	"github.com/kolide/krypto/pkg/testfunc"
	"github.com/stretchr/testify/require"
)

func TestBoxSigning(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in []byte
	}{
		{in: []byte("a")},
		{in: testfunc.Mkrand(t, 32)},
		{in: testfunc.Mkrand(t, 256)},
		{in: testfunc.Mkrand(t, 2048)},
		{in: testfunc.Mkrand(t, 4096)},
		{in: []byte(testfunc.RandomString(t, 4096))},
	}

	aliceKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	bobKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	aliceSigner := NewBoxer(keyencoder.New(aliceKey), nil)

	bobBoxer := NewBoxer(keyencoder.New(bobKey), aliceKey.Public().(*rsa.PublicKey))
	bareBobBoxer := NewBoxer(keyencoder.New(bobKey), nil)

	var testfunc = []struct {
		name      string
		fn        func([]byte) (*Box, error)
		expectErr bool
	}{
		{name: "bob can verify", fn: bobBoxer.DecodeRaw},
		{name: "bob can decode unverified", fn: bobBoxer.DecodeRawUnverified},
		{name: "bare bob can decode unverified", fn: bareBobBoxer.DecodeRawUnverified},

		{name: "bare bob cannot verify", fn: bareBobBoxer.DecodeRaw, expectErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			responseTo := ulid.New()

			signed, err := aliceSigner.Sign(responseTo, tt.in)
			require.NoError(t, err)

			for _, tf := range testfunc {
				tf := tf
				t.Run(tf.name, func(t *testing.T) {
					t.Parallel()
					if tf.expectErr {
						box, err := tf.fn(signed)
						require.Error(t, err)
						require.Nil(t, box)
					} else {
						box, err := tf.fn(signed)
						require.NoError(t, err)
						require.Equal(t, tt.in, box.Signedtext, "decoded matches")
					}
				})
			}

		})
	}
}

func TestBoxRandomRoundTrips(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in []byte
	}{
		{in: []byte("a")},
		{in: testfunc.Mkrand(t, 32)},
		{in: testfunc.Mkrand(t, 256)},
		{in: testfunc.Mkrand(t, 2048)},
		{in: testfunc.Mkrand(t, 4096)},
		{in: []byte(testfunc.RandomString(t, 4096))},
	}

	aliceKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	bobKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	malloryKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	aliceBoxer := NewBoxer(keyencoder.New(aliceKey), bobKey.Public().(*rsa.PublicKey))
	bobBoxer := NewBoxer(keyencoder.New(bobKey), aliceKey.Public().(*rsa.PublicKey))
	bareBobBoxer := NewBoxer(keyencoder.New(bobKey), nil)
	malloryBoxer := NewBoxer(keyencoder.New(malloryKey), aliceKey.Public().(*rsa.PublicKey))
	bareMalloryBoxer := NewBoxer(keyencoder.New(malloryKey), nil)

	var testfunc = []struct {
		name      string
		fn        func(string) (*Box, error)
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

				for _, tf := range testfunc {
					tf := tf
					t.Run(tf.name, func(t *testing.T) {
						t.Parallel()
						if tf.expectErr {
							box, err := tf.fn(ciphertext)
							require.Error(t, err)
							require.Nil(t, box)
						} else {
							box, err := tf.fn(ciphertext)
							require.NoError(t, err)
							require.Equal(t, tt.in, box.Data(), "decoded matches")
						}
					})
				}

			})

			t.Run("png", func(t *testing.T) {
				t.Parallel()
				responseTo := ulid.New()

				var buf bytes.Buffer
				require.NoError(t, aliceBoxer.EncodePng(responseTo, tt.in, &buf))

				box, err := bobBoxer.DecodePngUnverified(&buf)
				require.NoError(t, err)

				require.Equal(t, tt.in, box.Data(), "decoded matches")
			})
		})
	}
}

func TestNilNoPanic(t *testing.T) {
	t.Parallel()

	aliceKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	bobKey, err := rsafunc.RandomKey()
	require.NoError(t, err)

	workingBoxer := NewBoxer(keyencoder.New(aliceKey), bobKey.Public().(*rsa.PublicKey))
	ciphertext, err := workingBoxer.EncodeRaw(ulid.New(), testfunc.Mkrand(t, 32))
	require.NoError(t, err)

	_, err = workingBoxer.EncodeRaw("", nil)
	require.NoError(t, err)

	var tests = []struct {
		name  string
		boxer boxMaker
	}{
		{name: "all nil", boxer: NewBoxer(nil, nil)},
		{name: "nil counterparty", boxer: NewBoxer(keyencoder.New(aliceKey), nil)},
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
