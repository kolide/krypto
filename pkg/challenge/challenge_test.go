package challenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/kolide/kit/ulid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestChallengeHappyPath(t *testing.T) {
	t.Parallel()

	challengerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	challengeId := []byte(ulid.New())
	challengeData := []byte(ulid.New())
	requestData := []byte(ulid.New())

	var challengeOuterBoxBytes []byte
	var challengeResponsePngBytesSingleSigner []byte
	var challengePrivateEncryptionKey *[32]byte

	//nolint: paralleltest
	t.Run("challenger creates challenge", func(t *testing.T) {
		// generate the challenge
		challengeOuterBoxBytes, challengePrivateEncryptionKey, err = Generate(challengerPrivateKey, challengeId, challengeData, requestData)
		require.NoError(t, err)
	})

	var outerResponsePngBytesDoubleSigner []byte
	responderData := []byte(ulid.New())

	//nolint: paralleltest
	t.Run("responder receives challenge and creates response", func(t *testing.T) {
		challengeOuterBox, err := UnmarshalChallenge(challengeOuterBoxBytes)
		require.NoError(t, err)

		responderPrivateSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		responderPrivateSigningKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// try to get info before verifying, shouldn't work
		require.Empty(t, challengeOuterBox.RequestData())
		require.Equal(t, challengeOuterBox.Timestamp(), int64(-1))

		// try to response before verifying, shouldn't work
		_, err = challengeOuterBox.Respond(responderPrivateSigningKey, responderPrivateSigningKey2, responderData)
		require.Error(t, err)

		// try to verify with bad key
		malloryPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		require.Error(t, challengeOuterBox.Verify(malloryPrivateKey.PublicKey))

		// verify with correct key
		require.NoError(t, challengeOuterBox.Verify(challengerPrivateKey.PublicKey))

		// verify data
		require.WithinDuration(t, time.Now(), time.Unix(challengeOuterBox.Timestamp(), 0), time.Second*5)
		require.Equal(t, requestData, challengeOuterBox.RequestData())

		// generate response with nil signer2
		challengeResponsePngBytesSingleSigner, err = challengeOuterBox.RespondPng(responderPrivateSigningKey, nil, responderData)
		require.NoError(t, err)

		// generate response
		outerResponsePngBytesDoubleSigner, err = challengeOuterBox.RespondPng(responderPrivateSigningKey, responderPrivateSigningKey2, responderData)
		require.NoError(t, err)
	})

	//nolint: paralleltest
	t.Run("challenger handles response", func(t *testing.T) {
		for _, responsePngBytes := range [][]byte{challengeResponsePngBytesSingleSigner, outerResponsePngBytesDoubleSigner} {
			outerResponse, err := UnmarshalResponsePng(responsePngBytes)
			require.NoError(t, err)

			// verify id
			require.Equal(t, challengeId, outerResponse.ChallengeId)

			// try to open with a bad key
			_, malloryPrivKey, err := box.GenerateKey(rand.Reader)
			require.NoError(t, err)
			_, err = outerResponse.Open(*malloryPrivKey)
			require.Error(t, err)

			// open with legit key
			innerResponse, err := outerResponse.Open(*challengePrivateEncryptionKey)
			require.NoError(t, err)

			// verify data
			require.Equal(t, challengeData, innerResponse.ChallengeData)
			require.Equal(t, responderData, innerResponse.ResponseData)
			require.WithinDuration(t, time.Now(), time.Unix(innerResponse.Timestamp, 0), time.Second*5)
		}
	})
}
