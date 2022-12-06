//go:build windows
// +build windows

package krypto

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func (t *TpmEncoder) OpenTpm() (io.ReadWriteCloser, error) {
	if t.ExternalTpm != nil {
		return t.ExternalTpm, nil
	}

	return tpm2.OpenTPM()
}
