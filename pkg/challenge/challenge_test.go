package challenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChallenge(t *testing.T) {
	t.Parallel()

	challengerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	challenge := []byte("this is a challenge")

	challengeOuterBox, challengePrivEncKey, err := Generate(challengerPrivateKey, challenge)
	require.NoError(t, err)

	responderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	responderData := []byte("this is some responder data")

	responseOuterbox, err := RespondPng(responderPrivateKey, challengerPrivateKey.PublicKey, *challengeOuterBox, responderData)
	require.NoError(t, err)

	innerResponse, err := OpenResponsePng(*challengePrivEncKey, responseOuterbox)
	require.NoError(t, err)

	require.Equal(t, challenge, innerResponse.ChallengeData)
	require.Equal(t, responderData, innerResponse.ResponseData)
}
