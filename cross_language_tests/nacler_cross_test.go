package cross_language_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kolide/krypto/pkg/nacler"
	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	tpmTestUtil "github.com/kolide/krypto/pkg/nacler/keyers/tpm/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type rubyCmdData struct {
	Key          []byte
	Counterparty []byte
	Ciphertext   []byte
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

	bobRubyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		makeKeyer func(*testing.T) nacler.Keyer
	}{
		{
			name: "local ecdsa keyer",
			makeKeyer: func(t *testing.T) nacler.Keyer {
				aliceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return localecdsa.New(aliceKey)
			},
		},
		{
			name: "tpm keyer",
			makeKeyer: func(t *testing.T) nacler.Keyer {
				keyer := tpmTestUtil.TestTpmKeyer(t)
				return keyer
			},
		},
	}

	for _, naclerTest := range tests {
		aliceKeyer := naclerTest.makeKeyer(t)
		aliceGoPublicKey, err := aliceKeyer.PublicKey()
		require.NoError(t, err)

		aliceNacler, err := nacler.New(naclerTest.makeKeyer(t), bobRubyKey.PublicKey)
		require.NoError(t, err)

		for _, messageToSeal := range testMessages {
			messageToSeal := messageToSeal

			t.Run(fmt.Sprintf("Alice seals in go using %s, Bob opens in ruby", naclerTest.name), func(t *testing.T) {
				t.Parallel()

				sealed, err := aliceNacler.Seal(messageToSeal)
				require.NoError(t, err, "Alice should be able to seal")

				requireMalloryCantOpen(t, sealed, aliceGoPublicKey, bobRubyKey.PublicKey)

				rubyCmdData := rubyCmdData{
					Key:          privateEcKeyToPem(t, bobRubyKey),
					Counterparty: publicEcKeyToPem(t, &aliceGoPublicKey),
					Ciphertext:   sealed,
				}

				plainText := rubyNaclerExec(t, "open", rubyCmdData)
				require.Equal(t, string(messageToSeal), string(plainText))
			})

			t.Run(fmt.Sprintf("Bob seals in ruby, Alice opens in go using %s", naclerTest.name), func(t *testing.T) {
				t.Parallel()

				rubyCmdData := rubyCmdData{
					Key:          privateEcKeyToPem(t, bobRubyKey),
					Counterparty: publicEcKeyToPem(t, &aliceGoPublicKey),
					Plaintext:    string(messageToSeal),
				}

				sealed := rubyNaclerExec(t, "seal", rubyCmdData)

				plaintext, err := aliceNacler.Open(sealed)
				require.NoError(t, err, "Alice should be able to open")

				require.Equal(t, string(messageToSeal), string(plaintext))

				requireMalloryCantOpen(t, sealed, aliceGoPublicKey, bobRubyKey.PublicKey)
			})
		}
	}
}

// #nosec G306 -- Need readable files
func rubyNaclerExec(t *testing.T, rubyCmd string, inputData rubyCmdData) []byte {
	testCaseBytes, err := msgpack.Marshal(inputData)
	require.NoError(t, err)
	testCaseBytesBase64 := []byte(base64.StdEncoding.EncodeToString(testCaseBytes))

	dir := t.TempDir()
	inFilePath := filepath.Join(dir, "in")
	require.NoError(t, os.WriteFile(inFilePath, testCaseBytesBase64, 0644))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ruby", naclerRB, rubyCmd, inFilePath)
	out, err := cmd.CombinedOutput()

	require.NoError(t, ctx.Err())
	require.NoError(t, err, string(out))

	// trim the trailing \n in output
	out = []byte(strings.Trim(string(out), "\n"))

	out, err = base64.StdEncoding.DecodeString(string(out))
	require.NoError(t, err)

	return out
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

func requireMalloryCantOpen(t *testing.T, sealed []byte, counterParties ...ecdsa.PublicKey) {
	malloryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, publicKey := range counterParties {
		malloryNacler, err := nacler.New(localecdsa.New(malloryKey), publicKey)
		require.NoError(t, err)
		_, err = malloryNacler.Open(sealed)
		require.Error(t, err, "Mallory should not be able to open")
	}
}
