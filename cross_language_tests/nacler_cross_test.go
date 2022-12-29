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

	"github.com/kolide/krypto/pkg/nacler"
	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type rubyCmdData struct {
	Key          []byte
	Counterparty []byte
	Ciphertext   string
	Plaintext    string
}

const naclerRB = "./nacler.rb"

func TestNaclerRuby(t *testing.T) {
	t.Parallel()

	testMessages := [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}

	aliceGoLocalEcdsaKeyer, aliceGoKey := localEcdsaKeyer(t)

	bobRubyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	naclers := []*nacler.Nacler{
		nacler.New(aliceGoLocalEcdsaKeyer, bobRubyKey.PublicKey),
		//TODO: add tpm keyer
	}

	for _, aliceNacler := range naclers {
		aliceNacler := aliceNacler

		for _, messageToSeal := range testMessages {
			messageToSeal := messageToSeal

			t.Run("Alice seals in go, Bob opens in ruby", func(t *testing.T) {
				t.Parallel()

				sealed, err := aliceNacler.Seal(messageToSeal)
				require.NoError(t, err)

				rubyCmdData := rubyCmdData{
					Key:          privateEcKeyToPem(t, bobRubyKey),
					Counterparty: publicEcKeyToPem(t, &aliceGoKey.PublicKey),
					Ciphertext:   sealed,
				}

				plainText := rubyNaclerExec(t, "open", rubyCmdData)
				require.Equal(t, string(messageToSeal), plainText)
			})

			t.Run("Bob seals in ruby, Alice opens in go", func(t *testing.T) {
				t.Parallel()

				rubyCmdData := rubyCmdData{
					Key:          privateEcKeyToPem(t, bobRubyKey),
					Counterparty: publicEcKeyToPem(t, &aliceGoKey.PublicKey),
					Plaintext:    string(messageToSeal),
				}

				cipherText := rubyNaclerExec(t, "seal", rubyCmdData)

				plaintext, err := aliceNacler.Open(cipherText)
				require.NoError(t, err)

				require.Equal(t, string(messageToSeal), plaintext)
			})
		}
	}
}

// #nosec G306 -- Need readable files
func rubyNaclerExec(t *testing.T, rubyCmd string, inputData rubyCmdData) string {
	testCaseBytes, err := msgpack.Marshal(inputData)
	require.NoError(t, err)
	testCaseBytesBase64 := []byte(base64.StdEncoding.EncodeToString(testCaseBytes))

	dir := t.TempDir()
	inFilePath := filepath.Join(dir, "in")
	require.NoError(t, os.WriteFile(inFilePath, testCaseBytesBase64, 0644))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, naclerRB, rubyCmd, inFilePath)
	out, err := cmd.CombinedOutput()

	require.NoError(t, ctx.Err())
	require.NoError(t, err, string(out))

	return strings.TrimSuffix(string(out), "\n")
}

func localEcdsaKeyer(t *testing.T) (nacler.Keyer, *ecdsa.PrivateKey) {
	localEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return localecdsa.New(localEcdsaKey), localEcdsaKey
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
