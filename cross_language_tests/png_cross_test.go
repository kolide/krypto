package cross_language_tests

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/kolide/kit/ulid"
	"github.com/kolide/krypto"
	"github.com/stretchr/testify/require"
)

var (
	pngRB = "./png.rb"
)

func TestPngRuby(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dir = "/tmp/crosstest"
	var tests = []struct {
		in []byte
	}{
		//{in: []byte("a")},
		{in: mkrand(t, 30)},
		//{in: mkrand(t, 31)},
		//{in: mkrand(t, 32)},
		//{in: mkrand(t, 33)},
		//{in: mkrand(t, 34)},
		//{in: mkrand(t, 256)},
		//{in: mkrand(t, 2048)},
		//{in: mkrand(t, 4096)},
		//{in: []byte(randomString(t, 4096))},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			var pngBuf bytes.Buffer
			require.NoError(t, krypto.ToPng(&pngBuf, tt.in))

			uniq := ulid.New()
			pngfile := path.Join(dir, uniq+".png")
			resultFile := path.Join(dir, uniq+".dat")

			require.NoError(t, os.WriteFile(pngfile, pngBuf.Bytes(), 0644))

			cmd := exec.CommandContext(ctx, pngRB, "decode", pngfile, resultFile)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))

			res, err := os.ReadFile(resultFile)
			require.NoError(t, err)

			actual := base64Decode(t, string(res))

			require.Equal(t, tt.in, actual)
		})

	}
}
