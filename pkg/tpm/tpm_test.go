package tpm

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kolide/krypto/pkg/echelper"
	"github.com/stretchr/testify/require"
)

func TestTpmSigning(t *testing.T) {
	t.Parallel()

	tpm := tpmSimulatorFallback(t)

	priv, pub, err := CreateKey(WithExternalTpm(tpm))
	require.NoError(t, err)

	tpmSigner, err := New(priv, pub, WithExternalTpm(tpm))
	require.NoError(t, err)

	dataToSign := []byte("here is some data to sign")

	signature, err := echelper.Sign(tpmSigner, dataToSign)
	require.NoError(t, err, "should be able to sign data")

	publicKey := tpmSigner.Public().(*ecdsa.PublicKey)

	require.NoError(t, echelper.VerifySignature(*publicKey, dataToSign, signature))
}

func TestTpmErrors(t *testing.T) {
	t.Parallel()

	tpm := tpmSimulatorFallback(t)

	priv, pub, err := CreateKey(WithExternalTpm(tpm))
	require.NoError(t, err)

	alteredPriv := []byte("some random stuff")
	_, err = New(alteredPriv, pub, WithExternalTpm(tpm))
	require.Error(t, err, "should get error with malformed private bytes")
	require.ErrorContains(t, err, "loading signer handle")

	alteredPub := []byte("some more random stuff")
	_, err = New(priv, alteredPub, WithExternalTpm(tpm))
	require.Error(t, err, "should get error with malformed public bytes")
	require.ErrorContains(t, err, "loading signer handle")

	_, err = New(nil, nil, WithExternalTpm(tpm))
	require.Error(t, err, "should get error with nil private and public bytes")
	require.ErrorContains(t, err, "loading signer handle")

	_, err = New(priv, nil, WithExternalTpm(tpm))
	require.Error(t, err, "should get error with nil public bytes")
	require.ErrorContains(t, err, "loading signer handle")

	_, err = New(nil, pub, WithExternalTpm(tpm))
	require.Error(t, err, "should get error with nil private bytes")
	require.ErrorContains(t, err, "loading signer handle")
}

// tpmSimulatorFallback returns an tpm keyer using TPM hardware chip if available,
// otherwise it returns a tpm keyer using a tpm hardware chip simulator.
func tpmSimulatorFallback(t *testing.T) io.ReadWriteCloser {
	tpm, err := tpm2.OpenTPM()
	if err == nil {
		t.Cleanup(func() {
			checkTpmClose(t, tpm)
		})

		return tpm
	}

	// no working tpm, use simulator
	t.Log("no tpm found, using simulator")
	simulatedTpm, err := simulator.Get()
	require.NoError(t, err)

	t.Cleanup(func() {
		checkTpmClose(t, simulatedTpm)
	})

	return simulatedTpm
}

// checkTpmClose closes the simulator and asserts that there were no leaked handles.
func checkTpmClose(t *testing.T, rwc io.ReadWriteCloser) {
	for _, handle := range []tpm2.HandleType{
		tpm2.HandleTypeLoadedSession,
		tpm2.HandleTypeSavedSession,
		tpm2.HandleTypeTransient,
	} {
		handles, err := tpmHandles(rwc, handle)
		require.NoError(t, err)
		require.Empty(t, len(handles), fmt.Sprintf("test leaked handles: %v", handles))
	}

	require.NoError(t, rwc.Close())
}

// tpmHandles returns a slice of tpmutil.Handle objects of all handles within
// the TPM rw of type handleType.
func tpmHandles(rw io.ReadWriter, handleType tpm2.HandleType) ([]tpmutil.Handle, error) {
	// Handle type is determined by the most-significant octet (MSO) of the property.
	property := uint32(handleType) << 24

	vals, moreData, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, math.MaxUint32, property)
	if err != nil {
		return nil, err
	}
	if moreData {
		return nil, fmt.Errorf("tpm2.GetCapability() should never return moreData==true for tpm2.CapabilityHandles")
	}
	handles := make([]tpmutil.Handle, len(vals))
	for i, v := range vals {
		handle, ok := v.(tpmutil.Handle)
		if !ok {
			return nil, fmt.Errorf("unable to assert type tpmutil.Handle of value %#v", v)
		}
		handles[i] = handle
	}
	return handles, nil
}
