package nacler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	"github.com/stretchr/testify/require"
)

func TestNacler(t *testing.T) {
	t.Parallel()

	messageToSeal := "this is the plaintext of the sealed message"

	alicesLocalEcdsaKeyer, alicesPubKey := localEcdsaKeyer(t)

	bobsKeyer, bobsPubKey := localEcdsaKeyer(t)
	bobsNacler := New(bobsKeyer, alicesPubKey)

	naclers := []*Nacler{
		New(alicesLocalEcdsaKeyer, bobsPubKey),
		//TODO: add tpm keyer
	}

	for _, aliceNacler := range naclers {
		aliceNacler := aliceNacler

		t.Run("alice seal bob open", func(t *testing.T) {
			t.Parallel()

			sealed, err := aliceNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err)

			opened, err := bobsNacler.Open(sealed)
			require.NoError(t, err)

			require.Equal(t, messageToSeal, opened)
		})

		t.Run("bob seal alice open", func(t *testing.T) {
			t.Parallel()

			sealed, err := bobsNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err)

			opened, err := aliceNacler.Open(sealed)
			require.NoError(t, err)

			require.Equal(t, messageToSeal, opened)
		})
	}
}

func localEcdsaKeyer(t *testing.T) (Keyer, ecdsa.PublicKey) {
	localEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return localecdsa.New(localEcdsaKey), localEcdsaKey.PublicKey
}
