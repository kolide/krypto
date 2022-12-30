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

	aliceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobsNacler := New(localecdsa.New(bobKey), aliceKey.PublicKey)

	naclers := []*Nacler{
		New(localecdsa.New(aliceKey), bobKey.PublicKey),
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

			require.Equal(t, messageToSeal, string(opened))
		})

		t.Run("bob seal alice open", func(t *testing.T) {
			t.Parallel()

			sealed, err := bobsNacler.Seal([]byte(messageToSeal))
			require.NoError(t, err)

			opened, err := aliceNacler.Open(sealed)
			require.NoError(t, err)

			require.Equal(t, messageToSeal, string(opened))
		})
	}
}
