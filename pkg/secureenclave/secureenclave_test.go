//go:build darwin
// +build darwin

package secureenclave

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kolide/krypto/pkg/echelper"
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
	require.Contains(t, string(out), "PASS: TestSecureEnclaveSigning")
	require.Contains(t, string(out), "PASS: TestSecureEnclaveErrors")
	require.NotContains(t, string(out), "FAIL")
	t.Log(string(out))
}

func TestSecureEnclaveSigning(t *testing.T) {
	t.Parallel()

	if os.Getenv(testWrappedEnvVarKey) == "" {
		t.Skipf("\nskipping because %s env var was empty, test not being run from codesigned app with entitlements", testWrappedEnvVarKey)
	}

	t.Log("\nrunning wrapped tests with codesigned app and entitlements")

	tempKeyLookup, err := CreateKey(false)
	require.NoError(t, err)

	_, err = New(tempKeyLookup)
	require.Error(t, err, "should be not be able to create a secure enclave keyer from temp key")

	pubKeyLookup, err := CreateKey(true)
	require.NoError(t, err)

	seSigner, err := New(pubKeyLookup)
	require.NoError(t, err, "should be able to create a secure enclave keyer from an existing key")

	dataToSign := []byte("here is some data to sign")

	signature, err := echelper.Sign(seSigner, dataToSign)
	require.NoError(t, err, "should be able to sign data")

	publicKey := seSigner.Public().(*ecdsa.PublicKey)

	require.NoError(t, echelper.VerifySignature(publicKey, dataToSign, signature))
}

func TestSecureEnclaveErrors(t *testing.T) {
	t.Parallel()

	if os.Getenv(testWrappedEnvVarKey) == "" {
		t.Skipf("\nskipping because %s env var was empty, test not being run from codesigned app with entitlements", testWrappedEnvVarKey)
	}

	t.Log("\nrunning wrapped tests with codesigned app and entitlements")

	_, err := New(nil)
	require.Error(t, err, "new secure enclave keyer should error with nil existing key")
}

func copyFile(t *testing.T, source, destination string) {
	bytes, err := os.ReadFile(source)
	require.NoError(t, err)
	// #nosec G306 -- Need readable files
	require.NoError(t, os.WriteFile(destination, bytes, 0700))
}

func signApp(t *testing.T, appRootDir string) {
	codeSignId := os.Getenv("MACOS_CODESIGN_IDENTITY")
	require.NotEmpty(t, codeSignId, "need MACOS_CODESIGN_IDENTITY env var to sign app, such as [Mac Developer: Jane Doe (ABCD123456)]")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// #nosec G204 -- This triggers due to using env var in cmd, making exception for test
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
