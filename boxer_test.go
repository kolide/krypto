package krypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/kolide/kit/ulid"
	"github.com/stretchr/testify/require"
)

func TestBoxSigning(t *testing.T) {
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

	aliceSigner := NewKeyBoxer(aliceKey, nil, nil)

	bobBoxer := NewKeyBoxer(bobKey, aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))
	bareBobBoxer := NewKeyBoxer(bobKey, nil, nil)

	var testFuncs = []struct {
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

			for _, tf := range testFuncs {
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

func TestBoxTpmSigning(t *testing.T) { //nolint:paralleltest
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

	aliceSigner := NewTpmBoxer(nil, nil)

	bobKey, err := RsaRandomKey()
	require.NoError(t, err)

	bobBoxer := NewKeyBoxer(bobKey, aliceSigner.encoder.PublicSigningKey(), aliceSigner.encoder.PublicEncryptionKey())
	bareBobBoxer := NewKeyBoxer(bobKey, nil, nil)

	var testFuncs = []struct {
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
		t.Run("", func(t *testing.T) { //nolint:paralleltest
			responseTo := ulid.New()

			signed, err := aliceSigner.Sign(responseTo, tt.in)
			require.NoError(t, err)

			for _, tf := range testFuncs {
				tf := tf
				t.Run(tf.name, func(t *testing.T) { //nolint:paralleltest
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

	aliceBoxer := NewKeyBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))
	bobBoxer := NewKeyBoxer(bobKey, aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))
	bareBobBoxer := NewKeyBoxer(bobKey, nil, nil)
	malloryBoxer := NewKeyBoxer(malloryKey, aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))
	bareMalloryBoxer := NewKeyBoxer(malloryKey, nil, nil)

	var testFuncs = []struct {
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

				for _, tf := range testFuncs {
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

func TestBoxTpmRandomRoundTrips(t *testing.T) { //nolint:paralleltest

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

	malloryKey, err := RsaRandomKey()
	require.NoError(t, err)

	tpmEncoder := newTpmEncoder()
	tpmEncoder.openTpm = func() (io.ReadWriteCloser, error) {
		return simulator.Get()
	}

	bobTpmBoxer := NewTpmBoxer(aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))

	aliceKeyBoxer := NewKeyBoxer(aliceKey, bobTpmBoxer.encoder.PublicSigningKey(), bobTpmBoxer.encoder.PublicEncryptionKey())

	bareBobTpmBoxer := NewTpmBoxer(nil, nil)
	malloryKeyBoxer := NewKeyBoxer(malloryKey, aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))
	bareMalloryKeyBoxer := NewKeyBoxer(malloryKey, nil, nil)

	var testFuncs = []struct {
		name      string
		fn        func(string) (*Box, error)
		expectErr bool
	}{
		{name: "bob can decode", fn: bobTpmBoxer.Decode},
		{name: "bob can decode unverified", fn: bobTpmBoxer.DecodeUnverified},
		{name: "bare bob can decode unverified", fn: bareBobTpmBoxer.DecodeUnverified},

		{name: "mallory cannot decode", fn: malloryKeyBoxer.Decode, expectErr: true},
		{name: "mallory cannot decode unverified", fn: malloryKeyBoxer.DecodeUnverified, expectErr: true},
		{name: "bare mallory cannot decode", fn: bareMalloryKeyBoxer.Decode, expectErr: true},
		{name: "bare mallory cannot decode unverified", fn: bareMalloryKeyBoxer.DecodeUnverified, expectErr: true},
		{name: "bare bob cannot verify and decode", fn: bareBobTpmBoxer.Decode, expectErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("size %d", len(tt.in)), func(t *testing.T) {

			t.Run("roundtrips", func(t *testing.T) { //nolint:paralleltest
				responseTo := ulid.New()

				ciphertext, err := aliceKeyBoxer.Encode(responseTo, tt.in)
				require.NoError(t, err)
				require.NotContains(t, ciphertext, tt.in)

				for _, tf := range testFuncs {
					tf := tf
					t.Run(tf.name, func(t *testing.T) { //nolint:paralleltest
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
				require.NoError(t, aliceKeyBoxer.EncodePng(responseTo, tt.in, &buf))

				box, err := bobTpmBoxer.DecodePngUnverified(&buf)
				require.NoError(t, err)

				require.Equal(t, tt.in, box.Data(), "decoded matches")
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

	workingBoxer := NewKeyBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))
	ciphertext, err := workingBoxer.EncodeRaw(ulid.New(), mkrand(t, 32))
	require.NoError(t, err)

	_, err = workingBoxer.EncodeRaw("", nil)
	require.NoError(t, err)

	var tests = []struct {
		name  string
		boxer boxMaker
	}{
		{name: "all nil", boxer: NewKeyBoxer(nil, nil, nil)},
		{name: "nil counterparty", boxer: NewKeyBoxer(aliceKey, nil, nil)},
		{name: "nil me", boxer: NewKeyBoxer(nil, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))},
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
