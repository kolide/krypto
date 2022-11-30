package krypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

	tpmEncoder := testTpmEncoder(t)
	aliceTpmSigner := NewEncoderBoxer(tpmEncoder, nil, nil)

	bobKey, err := RsaRandomKey()
	require.NoError(t, err)

	aliceSigningKey, err := aliceTpmSigner.encoder.PublicSigningKey()
	require.NoError(t, err)

	aliceEncryptionKey, err := aliceTpmSigner.encoder.PublicEncryptionKey()
	require.NoError(t, err)

	bobBoxer := NewKeyBoxer(bobKey, aliceSigningKey, aliceEncryptionKey)
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

	for _, tt := range tests { //nolint:paralleltest
		tt := tt
		t.Run("", func(t *testing.T) {
			responseTo := ulid.New()

			signed, err := aliceTpmSigner.Sign(responseTo, tt.in)
			require.NoError(t, err)

			for _, tf := range testFuncs { //nolint:paralleltest
				tf := tf
				t.Run(tf.name, func(t *testing.T) {
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

	tpmEncoder := testTpmEncoder(t)

	bobTpmBoxer := NewEncoderBoxer(tpmEncoder, aliceKey.Public().(*rsa.PublicKey), aliceKey.Public().(*rsa.PublicKey))

	bobSigningKey, err := bobTpmBoxer.encoder.PublicSigningKey()
	require.NoError(t, err)

	bobEncryptionKey, err := bobTpmBoxer.encoder.PublicEncryptionKey()
	require.NoError(t, err)

	aliceKeyBoxer := NewKeyBoxer(aliceKey, bobSigningKey, bobEncryptionKey)

	bareBobTpmBoxer := NewEncoderBoxer(tpmEncoder, nil, nil)
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

func testTpmEncoder(t *testing.T) *tpmEncoder {
	tpmEncoder := &tpmEncoder{}
	tpm, err := tpmEncoder.openTpm()

	// have a working tpm
	if err == nil {
		t.Log("actual tpm found, using for tests")
		tpm.Close()
		return tpmEncoder
	}

	// no working tpm, use simulatoa
	t.Log("no tpm found, using simulator")
	simulatedTpm, err := simulator.Get()
	require.NoError(t, err)

	t.Cleanup(func() {
		CheckedClose(t, simulatedTpm)
	})

	tpmEncoder.externalTpm = simulatedTpm

	return tpmEncoder
}

// CheckedClose closes the simulator and asserts that there were no leaked handles.
func CheckedClose(t *testing.T, rwc io.ReadWriteCloser) {
	for _, handle := range []tpm2.HandleType{
		tpm2.HandleTypeLoadedSession,
		tpm2.HandleTypeSavedSession,
		tpm2.HandleTypeTransient,
	} {
		handles, err := Handles(rwc, handle)
		require.NoError(t, err)
		require.Empty(t, len(handles), fmt.Sprintf("test leaked handles: %v", handles))
	}

	require.NoError(t, rwc.Close())
}

// Handles returns a slice of tpmutil.Handle objects of all handles within
// the TPM rw of type handleType.
func Handles(rw io.ReadWriter, handleType tpm2.HandleType) ([]tpmutil.Handle, error) {
	// Handle type is determined by the most-significant octet (MSO) of the property.
	property := uint32(handleType) << 24

	vals, moreData, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, math.MaxUint32, property)
	if err != nil {
		return nil, err
	}
	if moreData {
		return nil, fmt.Errorf("tpm2.GetCapability() should never return moreData==true for tpm2.CapabilityHandles")
	}
	handles := make([]tpmutil.Handle, len(vals))
	for i, v := range vals {
		handle, ok := v.(tpmutil.Handle)
		if !ok {
			return nil, fmt.Errorf("unable to assert type tpmutil.Handle of value %#v", v)
		}
		handles[i] = handle
	}
	return handles, nil
}
