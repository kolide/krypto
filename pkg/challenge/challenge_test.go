package challenge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/kolide/krypto"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

func TestChallenge(t *testing.T) {
	t.Parallel()

	challengerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	challengeId := []byte("this is the challeng id")
	challenge := []byte("this is a challenge")

	challengeOuterBox, challengePrivEncKey, err := Generate(challengerPrivateKey, challengeId, challenge)
	require.NoError(t, err)

	responderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	responderData := []byte("this is some responder data")

	responseOuterbox, err := RespondPng(responderPrivateKey, challengerPrivateKey.PublicKey, *challengeOuterBox, responderData)
	require.NoError(t, err)

	var outerResponseBuf bytes.Buffer
	require.NoError(t, krypto.FromPng(bytes.NewBuffer(responseOuterbox), &outerResponseBuf))

	var outerResponse OuterResponse
	require.NoError(t, msgpack.Unmarshal(outerResponseBuf.Bytes(), &outerResponse))

	innerResponse, err := OpenResponsePng(*challengePrivEncKey, responseOuterbox)
	require.NoError(t, err)

	require.Equal(t, challenge, innerResponse.ChallengeData)
	require.Equal(t, challengeId, outerResponse.ChallengeId)
	require.Equal(t, responderData, innerResponse.ResponseData)
}
