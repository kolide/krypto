//go:build windows
// +build windows

package krypto

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func (t *tpmEncoder) openTpm() (io.ReadWriteCloser, error) {
	if t.externalTpm != nil {
		return t.externalTpm, nil
	}

	return tpm2.OpenTPM()
}
