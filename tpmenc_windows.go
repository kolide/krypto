//go:build windows
// +build windows

package krypto

import "github.com/google/go-tpm/tpm2"

func newTpmEncoder() *tpmEncoder {
	return &tpmEncoder{
		openTpm: tpm2.OpenTPM,
	}
}
