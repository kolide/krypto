//go:build darwin
// +build darwin

package krypto

import (
	"errors"
	"io"
)

func (t *TpmKeyer) openTpm() (io.ReadWriteCloser, error) {
	if t.ExternalTpm != nil {
		return t.ExternalTpm, nil
	}

	return nil, errors.New("external TPM required for darwin, but was nil")
}

func (t *TpmKeyer) TpmAvailable() bool {
	return false
}
