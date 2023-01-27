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

	challengeId := []byte("this is the challeng id")
	challengeData := []byte("this is a challenge")
	requestData := []byte("this is the request data")
	responderData := []byte("this is some responder data")

	var challengeOuterBoxBytes []byte
	var challengePrivateEncryptionKey *[32]byte

	//nolint: paralleltest
	t.Run("challenger creates challenge", func(t *testing.T) {
		// generate the challenge
		challengeOuterBoxBytes, challengePrivateEncryptionKey, err = Generate(challengerPrivateKey, challengeId, challengeData, requestData)
		require.NoError(t, err)
	})

	var outerResponsePngBytes []byte

	//nolint: paralleltest
	t.Run("responder receives challenge and creates response", func(t *testing.T) {
		challengeOuterBox, err := UnmarshalOuterChallenge(challengeOuterBoxBytes)
		require.NoError(t, err)

		// verify the box is legit
		require.NoError(t, challengeOuterBox.Verify(challengerPrivateKey.PublicKey))

		challengeRequestData, err := challengeOuterBox.RequestData()
		require.NoError(t, err)

		require.Equal(t, requestData, challengeRequestData)

		responderPrivateSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		outerResponsePngBytes, err = challengeOuterBox.RespondPng(responderPrivateSigningKey, responderData)
		require.NoError(t, err)
	})

	//nolint: paralleltest
	t.Run("challenger handles response", func(t *testing.T) {
		outerResponse, err := UnmarshalOuterResponsePng(outerResponsePngBytes)
		require.NoError(t, err)

		require.Equal(t, challengeId, outerResponse.ChallengeId)

		innerResponse, err := outerResponse.Open(*challengePrivateEncryptionKey)
		require.NoError(t, err)

		require.Equal(t, challengeData, innerResponse.ChallengeData)
		require.Equal(t, responderData, innerResponse.ResponseData)
	})
}
