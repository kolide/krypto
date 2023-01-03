//go:build windows
// +build windows

package tpmkeyer

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func (t *TpmKeyer) openTpm() (io.ReadWriteCloser, error) {
	if t.externalTpm != nil {
		return t.externalTpm, nil
	}

	return tpm2.OpenTPM("/dev/tpm0")
}

func (t *TpmKeyer) TpmAvailable() bool {
	tpm, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return false
	}
	defer tpm.Close()
	return true
}