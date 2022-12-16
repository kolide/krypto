package cross_language_tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/kolide/krypto/pkg/rsafunc"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type rsaCrossTestCase struct {
	Public     []byte
	Private    []byte
	Plaintext  []byte
	Ciphertext []byte
	Signature  []byte
	Verified   bool
}

var (
	rsaRB = "./rsa.rb"
)

func TestRsaRuby(t *testing.T) {
	t.Parallel()

	tests := []rsaCrossTestCase{
		{Plaintext: []byte("a")},
		{Plaintext: []byte("Hello World")},
		{Plaintext: mkrand(t, 128)},
	}

	//#nosec G306 -- Need readable files
	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			key, err := rsafunc.RandomKey()
			require.NoError(t, err)

			t.Run("setup", func(t *testing.T) {
				var privatePem bytes.Buffer
				require.NoError(t, rsafunc.PrivateKeyToPem(key, &privatePem))
				tt.Private = privatePem.Bytes()

				var publicPem bytes.Buffer
				require.NoError(t, rsafunc.PublicKeyToPem(key, &publicPem))
				tt.Public = publicPem.Bytes()
			})

			t.Run("go encrypt ruby decrypt", func(t *testing.T) {
				t.Parallel()
				tt := tt

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				dir := t.TempDir()
				testfile := path.Join(dir, "testcase.msgpack")

				ciphertext, err := rsafunc.Encrypt(&key.PublicKey, tt.Plaintext)
				require.NoError(t, err)
				tt.Ciphertext = ciphertext

				b, err := msgpack.Marshal(tt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				cmd := exec.CommandContext(ctx, rsaRB, "decrypt", testfile, path.Join(dir, "ruby-decrypt"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				res, err := os.ReadFile(path.Join(dir, "ruby-decrypt"))
				require.NoError(t, err)

				var actual rsaCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(res)), &actual))
				require.Equal(t, string(tt.Plaintext), string(actual.Plaintext))
			})

			t.Run("ruby encrypt go decrypt", func(t *testing.T) {
				t.Parallel()
				tt := tt

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				dir := t.TempDir()
				testfile := path.Join(dir, "testcase.msgpack")

				b, err := msgpack.Marshal(tt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				cmd := exec.CommandContext(ctx, rsaRB, "encrypt", testfile, path.Join(dir, "ruby-encrypt"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				res, err := os.ReadFile(path.Join(dir, "ruby-encrypt"))
				require.NoError(t, err)
				var actual rsaCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(res)), &actual))

				plaintext, err := rsafunc.Decrypt(key, actual.Ciphertext)
				require.NoError(t, err)
				require.Equal(t, tt.Plaintext, plaintext)
			})

			t.Run("go sign ruby verify", func(t *testing.T) {
				t.Parallel()
				tt := tt

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				dir := t.TempDir()
				testfile := path.Join(dir, "testcase.msgpack")

				sig, err := rsafunc.Sign(key, tt.Plaintext)
				require.NoError(t, err)
				tt.Signature = sig

				b, err := msgpack.Marshal(tt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				cmd := exec.CommandContext(ctx, rsaRB, "verify", testfile, path.Join(dir, "ruby-verify"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				res, err := os.ReadFile(path.Join(dir, "ruby-verify"))
				require.NoError(t, err)

				var actual rsaCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(res)), &actual))

				require.Equal(t, true, actual.Verified)
			})

			t.Run("ruby sign go verify", func(t *testing.T) {
				t.Parallel()
				tt := tt

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				dir := t.TempDir()
				testfile := path.Join(dir, "testcase.msgpack")

				b, err := msgpack.Marshal(tt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				cmd := exec.CommandContext(ctx, rsaRB, "sign", testfile, path.Join(dir, "ruby-signed"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				res, err := os.ReadFile(path.Join(dir, "ruby-signed"))
				require.NoError(t, err)
				var actual rsaCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(res)), &actual))

				verified := rsafunc.Verify(&key.PublicKey, tt.Plaintext, actual.Signature)
				require.NoError(t, verified)
			})
		})

	}

}
