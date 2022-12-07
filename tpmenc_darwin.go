//go:build darwin
// +build darwin

package krypto

import (
	"errors"
	"io"
)

func (t *TpmEncoder) OpenTpm() (io.ReadWriteCloser, error) {
	if t.ExternalTpm != nil {
		return t.ExternalTpm, nil
	}

	return nil, errors.New("external TPM required for darwin, but was nil")
}
