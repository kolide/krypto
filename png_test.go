package krypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPng(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in []byte
	}{
		{in: nil},
		{in: []byte{0}},
		{in: []byte("a")},
		{in: []byte("abcd")},
		{in: []byte("abcdefgh")},
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

			var pngBuf bytes.Buffer
			require.NoError(t, ToPng(&pngBuf, tt.in))

			var actual bytes.Buffer
			require.NoError(t, FromPng(&pngBuf, &actual))

			require.Equal(t, tt.in, actual.Bytes())
		})
	}

}
