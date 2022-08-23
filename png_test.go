package krypto

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/kolide/kit/ulid"
	"github.com/stretchr/testify/require"
)

func TestToPng(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in []byte
	}{
		{in: []byte("a")},
		{in: mkrand(t, 32)},
		{in: mkrand(t, 256)},
		{in: mkrand(t, 2048)},
		{in: mkrand(t, 4096)},
		{in: []byte(randomString(t, 4096))},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, ToPng(&buf, tt.in))

			require.NoError(t, os.WriteFile(path.Join("/tmp", "kpng", ulid.New()+".png"), buf.Bytes(), 0644))
		})
	}

}
