package nacler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	"github.com/kolide/krypto/pkg/nacler/keyers/tpmkeyer"
	"github.com/stretchr/testify/require"
)

func TestNacler(t *testing.T) {
	t.Parallel()

	messageToSeal := "this is the plaintext of the sealed message"

	bobKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		makeKeyer func(*testing.T) keyer
	}{
		{
			name: "local ecdsa keyer",
			makeKeyer: func(t *testing.T) keyer {
				aliceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return localecdsa.New(aliceKey)
			},
		},
		{
			name: "tpm keyer",
			makeKeyer: func(t *testing.T) keyer {
				keyer := testTpmKeyer(t)
				return keyer
			},
		},
	}

	for _, test := range tests {

		alicesKeyer := test.makeKeyer(t)
		alicesNacler := New(alicesKeyer, bobKey.PublicKey)

		alicePub, err := alicesKeyer.PublicKey()
		require.NoError(t, err)

		bobsNacler := New(localecdsa.New(bobKey), alicePub)

		malloryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("alice seals with %s, bob opens", test.name), func(t *testing.T) {
			t.Parallel()

			sealed, err := alicesNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err, "alice should be able to seal")

			opened, err := bobsNacler.Open(sealed)
			require.NoError(t, err, "bob should be able to open")

			require.Equal(t, messageToSeal, string(opened))

			_, err = New(localecdsa.New(malloryKey), alicePub).Open(sealed)
			require.Error(t, err, "mallory should not be able to open")
		})

		t.Run(fmt.Sprintf("bob seals, alice opens with %s", test.name), func(t *testing.T) {
			t.Parallel()

			sealed, err := bobsNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err, "bob should be able to seal")

			opened, err := alicesNacler.Open(sealed)
			require.NoError(t, err, "alice should be able to open")

			require.Equal(t, messageToSeal, string(opened))

			_, err = New(localecdsa.New(malloryKey), bobKey.PublicKey).Open(sealed)
			require.Error(t, err, "mallory should not be able to open")
		})
	}
}

func testTpmKeyer(t *testing.T) *tpmkeyer.TpmKeyer {
	tpmKeyer := tpmkeyer.New()

	// have a working tpm
	if tpmKeyer.TpmAvailable() {
		t.Log("actual tpm avaliable, using for tests")
		return tpmKeyer
	}

	// no working tpm, use simulator
	t.Log("no tpm found, using simulator")
	simulatedTpm, err := simulator.Get()
	require.NoError(t, err)

	t.Cleanup(func() {
		CheckedClose(t, simulatedTpm)
	})

	return tpmkeyer.New(tpmkeyer.WithExternalTpm(simulatedTpm))
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
