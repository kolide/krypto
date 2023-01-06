package testutil

import (
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	tpmkeyer "github.com/kolide/krypto/pkg/nacler/keyers/tpm"
	"github.com/stretchr/testify/require"
)

func TestTpmKeyer(t *testing.T) *tpmkeyer.TpmKeyer {
	tpmKeyer := tpmkeyer.New()

	// have a working tpm
	if tpmKeyer.TpmAvailable() {
		t.Log("actual tpm available, using for tests")
		return tpmKeyer
	}

	// no working tpm, use simulator
	t.Log("no tpm found, using simulator")
	simulatedTpm, err := simulator.Get()
	require.NoError(t, err)

	t.Cleanup(func() {
		checkTpmClose(t, simulatedTpm)
	})

	return tpmkeyer.New(tpmkeyer.WithExternalTpm(simulatedTpm))
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
