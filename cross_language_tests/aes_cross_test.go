package cross_language_tests

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/kolide/krypto"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type aesCrossTestCase struct {
	Key        []byte
	AuthData   []byte
	Plaintext  []byte
	Ciphertext []byte
}

var (
	aesRB = "./aes.rb"
)

func TestAesRuby(t *testing.T) {
	t.Parallel()

	tests := []aesCrossTestCase{
		{Plaintext: []byte("a")},
		{Plaintext: []byte("Hello World")},
		{Plaintext: []byte("This isn't super long, but it's at least a little long?")},
		{Plaintext: []byte(randomString(t, 1024))},
		{Plaintext: mkrand(t, 1024)},

		{AuthData: mkrand(t, 32), Plaintext: []byte("Hello World")},
		{AuthData: mkrand(t, 32), Plaintext: []byte(randomString(t, 1024))},
		{AuthData: mkrand(t, 32), Plaintext: mkrand(t, 1024)},
	}

	//#nosec G306 -- Need readable files
	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			testfile := path.Join(dir, "testcase.msgpack")

			t.Run("setup", func(t *testing.T) {
				if tt.Key == nil {
					tt.Key = mkrand(t, 32)
				}

				var err error
				tt.Ciphertext, err = krypto.AesEncrypt(tt.Key, tt.AuthData, tt.Plaintext)
				require.NoError(t, err)

				b, err := msgpack.Marshal(tt)

				require.NoError(t, err)
				require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))
			})

			t.Run("ruby decrypt go", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", aesRB, "decrypt", testfile, path.Join(dir, "ruby-decrypt-go"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err())
				require.NoError(t, err, string(out))

				res, err := os.ReadFile(path.Join(dir, "ruby-decrypt-go"))
				require.NoError(t, err)

				var actual aesCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(res)), &actual))
				require.Equal(t, string(tt.Plaintext), string(actual.Plaintext))
			})

			t.Run("go decrypt ruby", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", aesRB, "encrypt", testfile, path.Join(dir, "ruby-encrypted"))
				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err())
				require.NoError(t, err, string(out))

				testcaseRaw, err := os.ReadFile(path.Join(dir, "ruby-encrypted"))
				require.NoError(t, err)

				var testcase aesCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(testcaseRaw)), &testcase))

				plaintext, err := krypto.AesDecrypt(testcase.Key, testcase.AuthData, testcase.Ciphertext)
				require.NoError(t, err)
				require.Equal(t, string(tt.Plaintext), string(plaintext))
			})

		})

	}
}
