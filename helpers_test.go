package krypto

import (
	"crypto/rand"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const randomStringCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'\n"

func randomString(t *testing.T, n int) string {
	maxInt := big.NewInt(int64(len(randomStringCharset)))

	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		char, err := rand.Int(rand.Reader, maxInt)
		require.NoError(t, err)

		sb.WriteByte(randomStringCharset[int(char.Int64())])
	}
	return sb.String()
}

func mkrand(t *testing.T, size int) []byte {
	r := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, r)
	require.NoError(t, err)
	return r
}
