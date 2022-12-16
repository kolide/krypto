package krypto

import (
	"bytes"
	"testing"

	"github.com/kolide/krypto/pkg/testfunc"
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
		{in: testfunc.Mkrand(t, 30)},
		{in: testfunc.Mkrand(t, 31)},
		{in: testfunc.Mkrand(t, 32)},
		{in: testfunc.Mkrand(t, 33)},
		{in: testfunc.Mkrand(t, 34)},
		{in: testfunc.Mkrand(t, 256)},
		{in: testfunc.Mkrand(t, 2048)},
		{in: testfunc.Mkrand(t, 4096)},
		{in: []byte(testfunc.RandomString(t, 4096))},
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
