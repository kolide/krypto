//go:build darwin
// +build darwin

package secureenclave

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kolide/krypto/pkg/nacler"
	"github.com/kolide/krypto/pkg/nacler/keyers/localecdsa"
	"github.com/stretchr/testify/require"
)

const (
	testWrappedEnvVarKey = "SECURE_ENCLAVE_TEST_WRAPPED"
	macOsAppResourceDir  = "./test_app_resources"
)

// TestSecureEnclaveTestRunner creates a MacOS app with the binary of this packages tests, then signs the app with entitlements and runs the tests.
// This is done because in order to access secure enclave to run tests, we need MacOS entitlements.
// #nosec G306 -- Need readable files
func TestSecureEnclaveTestRunner(t *testing.T) {
	t.Parallel()

	if os.Getenv("CI") != "" {
		t.Skipf("\nskipping because %s env var was not empty, this is being run in a CI environment without access to secure enclave", testWrappedEnvVarKey)
	}

	if os.Getenv(testWrappedEnvVarKey) != "" {
		t.Skipf("\nskipping because %s env var was not empty, this is the execution of the codesigned app with entitlements", testWrappedEnvVarKey)
	}

	t.Log("\nexecuting wrapped tests with codesigned app and entitlements")

	// set up app bundle
	rootDir := t.TempDir()
	appRoot := filepath.Join(rootDir, "krypto_test.app")

	// make required dirs krypto_test.app/Contents/MacOS and add files
	require.NoError(t, os.MkdirAll(filepath.Join(appRoot, "Contents", "MacOS"), 0700))
	copyFile(t, filepath.Join(macOsAppResourceDir, "Info.plist"), filepath.Join(appRoot, "Contents", "Info.plist"))
	copyFile(t, filepath.Join(macOsAppResourceDir, "embedded.provisionprofile"), filepath.Join(appRoot, "Contents", "embedded.provisionprofile"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// build an executable containing the tests into the app bundle
	executablePath := filepath.Join(appRoot, "Contents", "MacOS", "krypto_test")
	out, err := exec.CommandContext(ctx, "go", "test", "-c", "--cover", "--race", "./", "-o", executablePath).CombinedOutput()
	require.NoError(t, ctx.Err())
	require.NoError(t, err, string(out))

	// sign app bundle
	signApp(t, appRoot)

	// run app bundle executable
	cmd := exec.CommandContext(ctx, executablePath, "-test.v")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", testWrappedEnvVarKey, "true"))
	out, err = cmd.CombinedOutput()
	require.NoError(t, ctx.Err())
	require.NoError(t, err, string(out))

	// ensure the test ran
	require.Contains(t, string(out), "PASS: TestSecureEnclaveKeyerHappyPath")
	require.Contains(t, string(out), "PASS: TestSecureEnclaveKeyerErrors")
	t.Log(string(out))
}

func TestSecureEnclaveKeyerHappyPath(t *testing.T) {
	t.Parallel()

	if os.Getenv(testWrappedEnvVarKey) == "" {
		t.Skipf("\nskipping because %s env var was empty, test not being run from codesigned app with entitlements", testWrappedEnvVarKey)
	}

	t.Log("\nrunning wrapped tests with codesigned app and entitlements")

	messageToSeal := "this is the plaintext of the sealed message"

	alicesSePublicKey, err := CreateKey()
	require.NoError(t, err)

	alicesSeKeyer, err := New(*alicesSePublicKey)
	require.NoError(t, err, "should be able to create a secure enclave keyer from an existing key")

	bobKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobsLocalEcdsaNacler, err := nacler.New(localecdsa.New(bobKey), *alicesSePublicKey)
	require.NoError(t, err)

	alicesSecureEnclaveNacler, err := nacler.New(alicesSeKeyer, bobKey.PublicKey)
	require.NoError(t, err)

	t.Run("Alice seals, Bob opens", func(t *testing.T) {
		t.Parallel()

		sealed, err := alicesSecureEnclaveNacler.Seal([]byte(messageToSeal))
		require.NoError(t, err, "Alice should be able to seal")

		opened, err := bobsLocalEcdsaNacler.Open(sealed)
		require.NoError(t, err, "Bob should be able to open")

		require.Equal(t, messageToSeal, string(opened))

		requireMalloryCantOpen(t, sealed, *alicesSePublicKey, bobKey.PublicKey)
	})

	t.Run("Bob seals, Alice opens", func(t *testing.T) {
		t.Parallel()

		sealed, err := bobsLocalEcdsaNacler.Seal([]byte(messageToSeal))
		require.NoError(t, err, "Bob should be able to seal")

		opened, err := alicesSecureEnclaveNacler.Open(sealed)
		require.NoError(t, err, "Alice should be able to open")

		require.Equal(t, messageToSeal, string(opened))

		requireMalloryCantOpen(t, sealed, *alicesSePublicKey, bobKey.PublicKey)
	})
}

func TestSecureEnclaveKeyerErrors(t *testing.T) {
	t.Parallel()

	if os.Getenv(testWrappedEnvVarKey) == "" {
		t.Skipf("\nskipping because %s env var was empty, test not being run from codesigned app with entitlements", testWrappedEnvVarKey)
	}

	t.Log("\nrunning wrapped tests with codesigned app and entitlements")

	t.Run("new secure enclave keyer with null existing key", func(t *testing.T) {
		t.Parallel()

		// make empty key, make sure coordinates are nil
		emptyKey := new(ecdsa.PublicKey)
		require.Nil(t, emptyKey.X)
		require.Nil(t, emptyKey.Y)

		_, err := New(*emptyKey)
		require.Error(t, err, "new secure enclave keyer should error with nil existing key")
	})

	t.Run("shared key with null counter party", func(t *testing.T) {
		t.Parallel()

		emptyKey := new(ecdsa.PublicKey)
		require.Nil(t, emptyKey.X)
		require.Nil(t, emptyKey.Y)

		pubkey, err := CreateKey()
		require.NoError(t, err)

		keyer, err := New(*pubkey)
		require.NoError(t, err, "should be able to create a brand new secure enclave keyer")

		_, err = keyer.SharedKey(*emptyKey)
		require.Error(t, err, "shared key call should error with nil counter party")
	})
}

func requireMalloryCantOpen(t *testing.T, sealed []byte, publicKeys ...ecdsa.PublicKey) {
	malloryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, publicKey := range publicKeys {
		malloryNacler, err := nacler.New(localecdsa.New(malloryKey), publicKey)
		require.NoError(t, err)
		_, err = malloryNacler.Open(sealed)
		require.Error(t, err, "Mallory should not be able to open")
	}
}

// #nosec G306 -- Need readable files
func copyFile(t *testing.T, source, destination string) {
	bytes, err := os.ReadFile(source)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(destination, bytes, 0700))
}

// #nosec G204 -- This triggers due to using env var in cmd, making exception for test
func signApp(t *testing.T, appRootDir string) {
	codeSignId := os.Getenv("MACOS_CODESIGN_IDENTITY")
	require.NotEmpty(t, codeSignId, "need MACOS_CODESIGN_IDENTITY env var to sign app, such as [Mac Developer: Jane Doe (ABCD123456)]")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"codesign",
		"--deep",
		"--force",
		"--options", "runtime",
		"--entitlements", filepath.Join(macOsAppResourceDir, "entitlements"),
		"--sign", codeSignId,
		"--timestamp",
		appRootDir,
	)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err())
	require.NoError(t, err, string(out))
}
