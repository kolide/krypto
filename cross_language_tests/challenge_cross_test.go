package cross_language_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kolide/kit/ulid"
	"github.com/kolide/krypto/pkg/challenge"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/nacl/box"
)

type rubyChallengeCmd struct {
	RubyPrivateSigningKey []byte
	ChallengePack         []byte
	ChallengerPublicKey   []byte
	ChallengeId           []byte
	ChallengeData         []byte
	ResponsePack          []byte
	ResponseData          []byte
}

func TestChallengeRuby(t *testing.T) {
	t.Parallel()

	testChallenges := [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}

	responderData := []byte("here is some data about the responder")

	for _, testChallenge := range testChallenges {
		testChallenge := testChallenge

		t.Run("Ruby challenges, Go responds with png", func(t *testing.T) {
			t.Parallel()

			rubyPrivateSigningKey := ecdsaKey(t)
			responderKey := ecdsaKey(t)
			dir := t.TempDir()

			challengeId := []byte(ulid.New())

			rubyChallengeCmdData := rubyChallengeCmd{
				RubyPrivateSigningKey: privateEcKeyToPem(t, rubyPrivateSigningKey),
				ChallengeData:         testChallenge,
				ChallengeId:           challengeId,
			}

			out, err := rubyChallengeExec("generate", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(out))

			var rubyChallengeOuter challenge.OuterChallenge
			require.NoError(t, msgpack.Unmarshal(out, &rubyChallengeOuter))

			response, err := challenge.RespondPng(responderKey, rubyPrivateSigningKey.PublicKey, rubyChallengeOuter, responderData)
			require.NoError(t, err)

			rubyChallengeCmdData = rubyChallengeCmd{
				ResponsePack: response,
			}

			out, err = rubyChallengeExec("open_response_png", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(out))

			var innerResponse challenge.InnerResponse
			require.NoError(t, msgpack.Unmarshal(out, &innerResponse))

			require.Equal(t, testChallenge, innerResponse.ChallengeData)
			require.Equal(t, responderData, innerResponse.ResponseData)
			require.WithinDuration(t, time.Now(), time.Unix(innerResponse.TimeStamp, 0), time.Second*5)
		})

		t.Run("Go challenges, Ruby responds", func(t *testing.T) {
			t.Parallel()

			challengerKey := ecdsaKey(t)
			dir := t.TempDir()

			challengeId := []byte(ulid.New())

			generatedChallenge, privEncryptionKey, err := challenge.Generate(challengerKey, challengeId, testChallenge)
			require.NoError(t, err)

			challengePack, err := msgpack.Marshal(generatedChallenge)
			require.NoError(t, err)

			rubyChallengeCmdData := rubyChallengeCmd{
				ChallengerPublicKey: publicEcKeyToPem(t, &challengerKey.PublicKey),
				ChallengePack:       challengePack,
				ResponseData:        responderData,
			}

			out, err := rubyChallengeExec("respond", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(out))

			var rubyResponseOuter challenge.OuterResponse
			require.NoError(t, msgpack.Unmarshal(out, &rubyResponseOuter))

			innerResponse, err := challenge.OpenResponse(*privEncryptionKey, rubyResponseOuter)
			require.NoError(t, err)

			require.Equal(t, testChallenge, innerResponse.ChallengeData)
			require.Equal(t, responderData, innerResponse.ResponseData)
			require.Equal(t, challengeId, rubyResponseOuter.ChallengeId)
			require.WithinDuration(t, time.Now(), time.Unix(innerResponse.TimeStamp, 0), time.Second*5)
		})
	}
}

func TestChallengeRubyTampering(t *testing.T) {
	t.Parallel()

	testChallenge := []byte("this is the original message")
	responderData := []byte("here is some data about the responder")

	t.Run("Ruby challenges, Go responds, Tamper With Challenge", func(t *testing.T) {
		t.Parallel()

		rubyPrivateSignignKey := ecdsaKey(t)
		responderKey := ecdsaKey(t)
		dir := t.TempDir()

		rubyChallengeCmdData := rubyChallengeCmd{
			RubyPrivateSigningKey: privateEcKeyToPem(t, rubyPrivateSignignKey),
			ChallengeData:         testChallenge,
		}

		out, err := rubyChallengeExec("generate", dir, rubyChallengeCmdData)
		require.NoError(t, err, string(out))

		var rubyChallengeOuter challenge.OuterChallenge
		require.NoError(t, msgpack.Unmarshal(out, &rubyChallengeOuter))

		tamperPub, _, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)

		tamperedInner, err := msgpack.Marshal(challenge.InnerChallenge{
			PublicEncryptionKey: *tamperPub,
			ChallengeData:       testChallenge,
		})
		require.NoError(t, err)

		rubyChallengeOuter.Msg = tamperedInner

		_, err = challenge.Respond(responderKey, rubyPrivateSignignKey.PublicKey, rubyChallengeOuter, responderData)
		require.ErrorContains(t, err, "invalid signature")
	})

	t.Run("Go challenges, Ruby responds, Tamper With Challenge", func(t *testing.T) {
		t.Parallel()

		challengerKey := ecdsaKey(t)
		dir := t.TempDir()

		generatedChallenge, _, err := challenge.Generate(challengerKey, []byte(ulid.New()), testChallenge)
		require.NoError(t, err)

		tamperPub, _, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)

		tamperedInner, err := msgpack.Marshal(challenge.InnerChallenge{
			PublicEncryptionKey: *tamperPub,
			ChallengeData:       testChallenge,
		})
		require.NoError(t, err)

		generatedChallenge.Msg = tamperedInner

		challengePack, err := msgpack.Marshal(generatedChallenge)
		require.NoError(t, err)

		rubyChallengeCmdData := rubyChallengeCmd{
			ChallengerPublicKey: publicEcKeyToPem(t, &challengerKey.PublicKey),
			ChallengePack:       challengePack,
			ResponseData:        responderData,
		}

		out, err := rubyChallengeExec("respond", dir, rubyChallengeCmdData)
		require.Error(t, err, string(out))
		require.Contains(t, string(out), "invalid signature")
	})
}

// #nosec G306 -- Need readable files
func rubyChallengeExec(rubyCmd, dir string, inputData rubyChallengeCmd) ([]byte, error) {
	testCaseBytes, err := msgpack.Marshal(inputData)
	if err != nil {
		return nil, err
	}

	testCaseBytesBase64 := []byte(base64.StdEncoding.EncodeToString(testCaseBytes))

	inFilePath := filepath.Join(dir, "in")

	if err := os.WriteFile(inFilePath, testCaseBytesBase64, 0644); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ruby", "./challenge.rb", rubyCmd, inFilePath)
	out, err := cmd.CombinedOutput()

	// trim the trailing \n in output
	out = []byte(strings.Trim(string(out), "\n"))

	if err != nil {
		return out, err
	}

	out, err = base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		return nil, err
	}

	return out, nil
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func privateEcKeyToPem(t *testing.T, private *ecdsa.PrivateKey) []byte {
	bytes, err := x509.MarshalECPrivateKey(private)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes})
}

func publicEcKeyToPem(t *testing.T, public *ecdsa.PublicKey) []byte {
	bytes, err := x509.MarshalPKIXPublicKey(public)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes})
}
