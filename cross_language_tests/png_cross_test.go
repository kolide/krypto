package cross_language_tests

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path"
	"runtime"
	"testing"

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

	var tests = []struct {
		in []byte
	}{
		{in: []byte("a")},
		{in: []byte("abcd")},
		{in: mkrand(t, 30)},
		{in: mkrand(t, 31)},
		{in: mkrand(t, 32)},
		{in: mkrand(t, 33)},
		{in: mkrand(t, 34)},
		{in: mkrand(t, 256)},
		{in: mkrand(t, 2048)},
		{in: mkrand(t, 4096)},
		{in: []byte(randomString(t, 4096))},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			t.Parallel()

			pngfile := path.Join(dir, ulid.New()+".png")

			t.Run("setup", func(t *testing.T) {
				var pngBuf bytes.Buffer
				require.NoError(t, krypto.ToPng(&pngBuf, tt.in))

				require.NoError(t, os.WriteFile(pngfile, pngBuf.Bytes(), 0600))
			})

			for _, routine := range []string{"decode-file", "decode-blob", "decode-io"} {
				routine := routine

				t.Run(routine, func(t *testing.T) {
					t.Parallel()

					if runtime.GOOS == "windows" {
						t.Skip("skip png decode test on windows because ruby library chunky_png is looking for CRLF png signature")
					}

					ctx, cancel := context.WithTimeout(context.Background(), rubyCmdTimeout)
					defer cancel()

					resultFile := path.Join(dir, ulid.New()+".dat")

					cmd := exec.CommandContext(ctx, "ruby", pngRB, routine, pngfile, resultFile)
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, string(out))
					require.NoError(t, ctx.Err())

					res, err := os.ReadFile(resultFile)
					require.NoError(t, err)

					actual := base64Decode(t, string(res))

					require.Equal(t, tt.in, actual)
				})
			}
		})

	}
}
