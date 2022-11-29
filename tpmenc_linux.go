//go:build linux
// +build linux

package krypto

func newTpmEncoder() *tpmEncoder {
	return &tpmEncoder{
		openTpm: tpm2.OpenTPM("/dev/tpm0"),
	}
}
