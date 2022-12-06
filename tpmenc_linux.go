//go:build linux
// +build linux

package krypto

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func (t *tpmEncoder) OpenTpm() (io.ReadWriteCloser, error) {
	if t.externalTpm != nil {
		return t.externalTpm, nil
	}

	return tpm2.OpenTPM("/dev/tpm0")
}
