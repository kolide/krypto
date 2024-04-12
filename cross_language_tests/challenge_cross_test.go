package cross_language_tests

import (
	"bytes"
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
	"github.com/kolide/krypto"
	"github.com/kolide/krypto/pkg/challenge"
	"github.com/kolide/krypto/pkg/echelper"
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
	RequestData           []byte
	ResponsePack          []byte
	ResponseData          []byte
}

func TestChallenge_RubyGenerate_GoRespondPng(t *testing.T) {
	t.Parallel()

	//nolint: paralleltest
	for _, challengeData := range testChallenges(t) {
		dir := t.TempDir()

		rubyPrivateSigningKey := ecdsaKey(t)
		challengeId := []byte(ulid.New())
		requestData := []byte(ulid.New())

		var challengeOuterBoxBytes []byte

		t.Run("ruby creates challenge", func(t *testing.T) {
			rubyChallengeCmdData := rubyChallengeCmd{
				RubyPrivateSigningKey: privateEcKeyToPem(t, rubyPrivateSigningKey),
				ChallengeData:         challengeData,
				ChallengeId:           challengeId,
				RequestData:           requestData,
			}

			out, err := rubyChallengeExec("generate", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(out))
			challengeOuterBoxBytes = out
		})

		t.Run("go receives tampered with challenge and fails to verify", func(t *testing.T) {
			outerChallenge, err := challenge.UnmarshalChallenge(tamperWithChallenge(t, challengeOuterBoxBytes))
			require.NoError(t, err)

			require.ErrorContains(t, outerChallenge.Verify(rubyPrivateSigningKey.PublicKey), "invalid signature", "should get an eror due to tampering")
		})

		var outerResponsePngBytes []byte
		responderData := []byte(ulid.New())

		t.Run("go receives legit challenge and creates response png", func(t *testing.T) {
			challengeOuterBox, err := challenge.UnmarshalChallenge(challengeOuterBoxBytes)
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
			require.NoError(t, challengeOuterBox.Verify(rubyPrivateSigningKey.PublicKey))

			// verify data
			require.WithinDuration(t, time.Now(), time.Unix(challengeOuterBox.Timestamp(), 0), time.Second*5)
			require.Equal(t, requestData, challengeOuterBox.RequestData())

			// generate response with nil signer2
			_, err = challengeOuterBox.RespondPng(responderPrivateSigningKey, nil, responderData)
			require.NoError(t, err)

			// generate response
			outerResponsePngBytes, err = challengeOuterBox.RespondPng(responderPrivateSigningKey, responderPrivateSigningKey2, responderData)
			require.NoError(t, err)
		})

		t.Run("ruby receives tampered with response, fails to verify", func(t *testing.T) {
			rubyChallengeCmdData := rubyChallengeCmd{
				ResponsePack: tamperWithPngResponse(t, challengeOuterBoxBytes, outerResponsePngBytes),
			}

			out, err := rubyChallengeExec("open_response_png", dir, rubyChallengeCmdData)
			require.Error(t, err)
			require.Contains(t, string(out), "invalid signature")
		})

		t.Run("ruby handles legit response", func(t *testing.T) {
			rubyChallengeCmdData := rubyChallengeCmd{
				ResponsePack: outerResponsePngBytes,
			}

			// make sure the challenge id persisted
			responseBox, err := challenge.UnmarshalResponsePng(outerResponsePngBytes)
			require.NoError(t, err)
			require.Equal(t, challengeId, responseBox.ChallengeId)

			out, err := rubyChallengeExec("open_response_png", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(out))

			var innerResponse challenge.InnerResponse
			require.NoError(t, msgpack.Unmarshal(out, &innerResponse))

			require.Equal(t, challengeData, innerResponse.ChallengeData)
			require.Equal(t, responderData, innerResponse.ResponseData)
			require.WithinDuration(t, time.Now(), time.Unix(innerResponse.Timestamp, 0), time.Second*5)
		})
	}
}

func TestChallenge_GoGenerate_RubyRespond(t *testing.T) {
	t.Parallel()

	//nolint: paralleltest
	for _, challengeData := range testChallenges(t) {
		dir := t.TempDir()

		goPrivateSigningKey := ecdsaKey(t)
		challengeId := []byte(ulid.New())
		requestData := []byte(ulid.New())

		var challengeOuterBoxBytes []byte
		var challengePrivateEncryptionKey *[32]byte

		t.Run("go creates challenge", func(t *testing.T) {
			out, key, err := challenge.Generate(goPrivateSigningKey, challengeId, challengeData, requestData)
			require.NoError(t, err, string(challengeOuterBoxBytes))

			challengeOuterBoxBytes = out
			challengePrivateEncryptionKey = key
		})

		var outerResponseBytes []byte
		responderData := []byte(ulid.New())

		t.Run("ruby receives tampered with challenge and and fails to verify", func(t *testing.T) {
			rubyChallengeCmdData := rubyChallengeCmd{
				ChallengerPublicKey: publicEcKeyToPem(t, &goPrivateSigningKey.PublicKey),
				ChallengePack:       tamperWithChallenge(t, challengeOuterBoxBytes),
				ResponseData:        responderData,
			}
			out, err := rubyChallengeExec("respond", dir, rubyChallengeCmdData)
			require.Error(t, err, string(outerResponseBytes))
			require.Contains(t, string(out), "verification failed")
		})

		t.Run("ruby receives challenge and creates response", func(t *testing.T) {
			rubyChallengeCmdData := rubyChallengeCmd{
				ChallengerPublicKey: publicEcKeyToPem(t, &goPrivateSigningKey.PublicKey),
				ChallengePack:       challengeOuterBoxBytes,
				ResponseData:        responderData,
			}
			out, err := rubyChallengeExec("respond", dir, rubyChallengeCmdData)
			require.NoError(t, err, string(outerResponseBytes))

			outerResponseBytes = out
		})

		t.Run("go recives tampered with response and fails to verify", func(t *testing.T) {
			outerResponse, err := challenge.UnmarshalResponse(tamperWithResponse(t, challengeOuterBoxBytes, outerResponseBytes))
			require.NoError(t, err)

			_, err = outerResponse.Open(*challengePrivateEncryptionKey)
			require.Error(t, err)
		})

		t.Run("go handles legit response", func(t *testing.T) {
			outerResponse, err := challenge.UnmarshalResponse(outerResponseBytes)
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
		})
	}
}

func TestChallenge_MaxSize(t *testing.T) {
	t.Parallel()

	tooBigBytes := mkrand(t, krypto.V0MaxSize+1)

	t.Run("max size enforced in go", func(t *testing.T) {
		t.Parallel()
		_, err := challenge.UnmarshalChallenge(tooBigBytes)
		require.ErrorContains(t, err, "exceeds max size", "should get an error due to size")
	})

	t.Run("max size enforced in ruby", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		rubyPrivateSigningKey := ecdsaKey(t)

		rubyChallengeCmdData := rubyChallengeCmd{
			RubyPrivateSigningKey: privateEcKeyToPem(t, rubyPrivateSigningKey),
		}

		out, err := rubyChallengeExec("generate", dir, rubyChallengeCmdData)
		require.NoError(t, err, string(out))

		rubyChallengeCmdData = rubyChallengeCmd{
			ResponsePack: tooBigBytes,
		}

		out, err = rubyChallengeExec("open_response_png", dir, rubyChallengeCmdData)
		require.Error(t, err, string(out))
		require.Contains(t, string(out), "response too large", "should get an error due to size")
	})
}

func rubyChallengeExec(rubyCmd, dir string, inputData rubyChallengeCmd) ([]byte, error) {
	testCaseBytes, err := msgpack.Marshal(inputData)
	if err != nil {
		return nil, err
	}

	testCaseBytesBase64 := []byte(base64.StdEncoding.EncodeToString(testCaseBytes))

	inFilePath := filepath.Join(dir, "in")

	//#nosec G306 -- Need readable files
	err = os.WriteFile(inFilePath, testCaseBytesBase64, 0644)
	if err != nil {
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

func testChallenges(t *testing.T) [][]byte {
	return [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}
}

func tamperWithChallenge(t *testing.T, challengeBytes []byte) []byte {
	challengeBox, err := challenge.UnmarshalChallenge(challengeBytes)
	require.NoError(t, err)

	var innerChallenge challenge.InnerChallenge
	require.NoError(t, msgpack.Unmarshal(challengeBox.Msg, &innerChallenge))

	innerChallenge.RequestData = []byte("do something evil!")

	challengeBox.Msg, err = msgpack.Marshal(innerChallenge)
	require.NoError(t, err)

	tamperedChallengeOuterBoxBytes, err := challengeBox.Marshal()
	require.NoError(t, err)

	return tamperedChallengeOuterBoxBytes
}

func tamperWithResponse(t *testing.T, challengeBytes, responseBytes []byte) []byte {
	malloryKey := ecdsaKey(t)

	malloryKeyDerBytes, err := x509.MarshalPKIXPublicKey(&malloryKey.PublicKey)
	require.NoError(t, err)

	malloryB64Der := base64.StdEncoding.EncodeToString(malloryKeyDerBytes)

	outerChallenge, err := challenge.UnmarshalChallenge(challengeBytes)
	require.NoError(t, err)

	var innerChallenge challenge.InnerChallenge
	require.NoError(t, msgpack.Unmarshal(outerChallenge.Msg, &innerChallenge))

	innerResponseBytes, err := msgpack.Marshal(challenge.InnerResponse{
		PublicSigningKey:  []byte(malloryB64Der),
		PublicSigningKey2: []byte(malloryB64Der),
		ChallengeData:     innerChallenge.ChallengeData,
		ResponseData:      []byte("evil response data"),
		Timestamp:         time.Now().Unix(),
	})
	require.NoError(t, err)

	// generate our own keys
	naclBox, pubKey, err := echelper.SealNaCl(innerResponseBytes, &innerChallenge.PublicEncryptionKey)
	require.NoError(t, err)

	outerResponse, err := challenge.UnmarshalResponse(responseBytes)
	require.NoError(t, err)

	outerResponse.PublicEncryptionKey = *pubKey
	outerResponse.Msg = naclBox

	tamperedBytes, err := msgpack.Marshal(outerResponse)
	require.NoError(t, err)

	return tamperedBytes
}

func tamperWithPngResponse(t *testing.T, challengeBytes, pngResponseBytes []byte) []byte {
	in := bytes.NewBuffer(pngResponseBytes)
	var out bytes.Buffer
	require.NoError(t, krypto.FromPng(in, &out))

	var pngBuf bytes.Buffer
	require.NoError(t, krypto.ToPng(&pngBuf, tamperWithResponse(t, challengeBytes, out.Bytes())))

	return pngBuf.Bytes()
}
