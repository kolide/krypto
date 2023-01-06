package nacler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	tpmTestUtil "github.com/kolide/krypto/pkg/nacler/keyers/tpm/testutil"

	"github.com/stretchr/testify/require"
)

func TestNacler(t *testing.T) {
	t.Parallel()

	messageToSeal := "this is the plaintext of the sealed message"

	bobKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		makeKeyer func(*testing.T) Keyer
	}{
		{
			name: "local ecdsa keyer",
			makeKeyer: func(t *testing.T) Keyer {
				aliceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return localecdsa.New(aliceKey)
			},
		},
		{
			name: "tpm keyer",
			makeKeyer: func(t *testing.T) Keyer {
				keyer := tpmTestUtil.TestTpmKeyer(t)
				return keyer
			},
		},
	}

	for _, test := range tests {
		alicesKeyer := test.makeKeyer(t)
		alicesNacler, err := New(alicesKeyer, bobKey.PublicKey)
		require.NoError(t, err)

		alicePub, err := alicesKeyer.PublicKey()
		require.NoError(t, err)

		bobsNacler, err := New(localecdsa.New(bobKey), alicePub)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("Alice seals with %s, Bob opens", test.name), func(t *testing.T) {
			t.Parallel()

			sealed, err := alicesNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err, "Alice should be able to seal")

			opened, err := bobsNacler.Open(sealed)
			require.NoError(t, err, "Bob should be able to open")

			require.Equal(t, messageToSeal, string(opened))

			requireMalloryCantOpen(t, sealed, alicePub, bobKey.PublicKey)
		})

		t.Run(fmt.Sprintf("Bob seals, Alice opens with %s", test.name), func(t *testing.T) {
			t.Parallel()

			sealed, err := bobsNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err, "Bob should be able to seal")

			opened, err := alicesNacler.Open(sealed)
			require.NoError(t, err, "Alice should be able to open")

			require.Equal(t, messageToSeal, string(opened))

			requireMalloryCantOpen(t, sealed, alicePub, bobKey.PublicKey)
		})
	}
}

func requireMalloryCantOpen(t *testing.T, sealed []byte, publicKeys ...ecdsa.PublicKey) {
	malloryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, publicKey := range publicKeys {
		malloryNacler, err := New(localecdsa.New(malloryKey), publicKey)
		require.NoError(t, err)
		_, err = malloryNacler.Open(sealed)
		require.Error(t, err, "Mallory should not be able to open")
	}
}
