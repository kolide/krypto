//go:build darwin
// +build darwin
import (
	"github.com/google/go-tpm/tpm2"
)

package krypto

func newTpmEncoder() *tpmEncoder {
	return nil
}
