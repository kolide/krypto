//go:build darwin
// +build darwin

// These tests check against the historical, deprecated crypto APIs.
package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// A key valid with the prior parsing API to confirm the new one works too.
const (
	workingRawHex  = "04663bf75236351ee6f6223c4fd4f95174f06e7423c58fcd2f9f64068538a93aeb44e70f697668f352f6aba95f4c5a92141b7153d1bf984f7f25b64363e302f04a"
	workingSha1Hex = "f83f03e13fed812ee5072bf3148ca6a1a28267fa"
)

// Key that previously worked with the prior system.
func TestPublicKeyKnownGood(t *testing.T) {
	t.Parallel()

	raw, err := hex.DecodeString(workingRawHex)
	require.NoError(t, err)

	key, err := rawToEcdsa(raw)
	require.NoError(t, err)

	hash, err := publicKeyLookUpHash(key)
	require.NoError(t, err)
	require.Equal(t, workingSha1Hex, hex.EncodeToString(hash))
}

// Unguarded implementation from crypto/ecdsa panics.
func TestPublicKeyLookUpHashNilCoordinates(t *testing.T) {
	t.Parallel()

	_, err := publicKeyLookUpHash(&ecdsa.PublicKey{Curve: elliptic.P256()})
	require.Error(t, err)
}
