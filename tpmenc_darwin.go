//go:build darwin
// +build darwin

package krypto

import (
	"errors"
	"io"
)

func (t *tpmEncoder) openTpm() (io.ReadWriteCloser, error) {
	return nil, errors.New("not implemented")
}