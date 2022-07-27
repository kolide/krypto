package cross_language_tests

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/kolide/kit/ulid"
	"github.com/kolide/krypto"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type boxerCrossTestCase struct {
	Key          []byte
	Counterparty []byte
	Plaintext    []byte
	Ciphertext   string
	name         string
	expectErr    bool
	cmd          string
}

var (
	boxerRB = "./boxer.rb"
)

func TestBoxerRuby(t *testing.T) {
	t.Parallel()

	//
	// Setup keys and similar.
	//
	aliceKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var alicePubPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(aliceKey, &alicePubPem))

	bobKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var bobPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(bobKey, &bobPem))

	malloryKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var malloryPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(malloryKey, &malloryPem))

	aliceBoxer := krypto.NewBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey))

	testMessages := [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}

	for _, message := range testMessages {
		message := message
		responseTo := ulid.New()
		ciphertext, err := aliceBoxer.Encode(responseTo, message)
		require.NoError(t, err)

		tests := []boxerCrossTestCase{
			// Go encoded, ruby successfully decode
			{Key: bobPem.Bytes(), Counterparty: alicePubPem.Bytes(), Ciphertext: ciphertext, cmd: "decode"},
			{Key: bobPem.Bytes(), Counterparty: alicePubPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},
			{Key: bobPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},

			// Go encoded, ruby cannot decode with wrong keys
			{Key: bobPem.Bytes(), cmd: "decode", expectErr: true},
			{Key: malloryPem.Bytes(), Counterparty: alicePubPem.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
			{Key: malloryPem.Bytes(), Counterparty: alicePubPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},
			{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
			{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},

			// Ruby encoded
			//{Key: aliceKey, Counterparty: bobKey.Public().(*rsa.PublicKey), cmd: "encode"},
		}

		//#nosec G306 -- Need readable files
		for _, tt := range tests {
			tt := tt

			t.Run("", func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()
				testfile := path.Join(dir, ulid.New()) //"testcase.msgpack")
				rubyout := path.Join(dir, ulid.New())  //"ruby-out")

				//
				// Setup
				//
				b, err := msgpack.Marshal(tt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				cmd := exec.CommandContext(ctx, boxerRB, tt.cmd, testfile, rubyout)
				out, err := cmd.CombinedOutput()

				//
				// Check
				//
				if tt.expectErr {
					require.Error(t, err)
					return
				}

				require.NoError(t, err, string(out))

				rubyResult, err := os.ReadFile(rubyout)
				require.NoError(t, err)

				var actual boxerCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &actual))

				require.Equal(t, message, actual.Plaintext, "plaintext matches")

			})
		}

	}
}
