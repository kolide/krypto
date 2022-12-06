package cross_language_tests

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kolide/kit/ulid"
	"github.com/kolide/krypto"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type boxerCrossTestCase struct {
	Key                       []byte
	CounterpartySigningKey    []byte
	CounterpartyEncryptionKey []byte
	Plaintext                 []byte
	Ciphertext                string
	PngFile                   string
	ResponseTo                string
	expectErr                 bool
	cmd                       string
}

var (
	boxerRB    = "./boxer.rb"
	ctxTimeout = 10 * time.Second
)

func TestKeyBoxerRuby(t *testing.T) {
	t.Parallel()

	//
	// Setup keys and similar.
	//
	aliceKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)

	var alicePubSigningKey bytes.Buffer
	require.NoError(t, krypto.RsaPrivateToPubicPem(aliceKey, &alicePubSigningKey))

	var alicePubEncryptionKey bytes.Buffer
	require.NoError(t, krypto.RsaPrivateToPubicPem(aliceKey, &alicePubEncryptionKey))

	bobKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var bobPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(bobKey, &bobPem))

	malloryKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var malloryPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(malloryKey, &malloryPem))

	aliceBoxer := krypto.NewKeyBoxer(aliceKey, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))
	bareAliceBoxer := krypto.NewKeyBoxer(aliceKey, nil, nil)
	malloryBoxer := krypto.NewKeyBoxer(malloryKey, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))
	bareMalloryBoxer := krypto.NewKeyBoxer(malloryKey, nil, nil)

	testMessages := [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}

	// Ruby Decrypt Tests
	//#nosec G306 -- Need readable files
	for _, message := range testMessages {
		message := message

		t.Run("ruby encrypt go decrypt", func(t *testing.T) {
			t.Parallel()

			var ciphertext string

			t.Run("ruby encrypt", func(t *testing.T) {
				dir := t.TempDir()
				rubyInFile := filepath.Join(dir, "testcase.msgpack")
				rubyOutFile := filepath.Join(dir, "ruby-out")

				rubyCommand := boxerCrossTestCase{
					Key:                       bobPem.Bytes(),
					CounterpartySigningKey:    alicePubSigningKey.Bytes(),
					CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(),
					Plaintext:                 message,
					ResponseTo:                ulid.New(),
				}

				b, err := msgpack.Marshal(rubyCommand)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(rubyInFile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", boxerRB, "encode", rubyInFile, rubyOutFile)

				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err())
				require.NoError(t, err, string(out))

				rubyResult, err := os.ReadFile(rubyOutFile)
				require.NoError(t, err)

				var unpacked boxerCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &unpacked))

				require.NotEmpty(t, unpacked.Ciphertext)
				ciphertext = unpacked.Ciphertext
			})

			var testFuncs = []struct {
				name       string
				fn         func(string) (*krypto.Box, error)
				expectErr  bool
				ciphertext string
			}{
				{name: "alice can decode", ciphertext: ciphertext, fn: aliceBoxer.Decode},
				{name: "alice can decode unverified", ciphertext: ciphertext, fn: aliceBoxer.DecodeUnverified},
				{name: "bare alice can decode unverified", ciphertext: ciphertext, fn: bareAliceBoxer.DecodeUnverified},

				{name: "mallory cannot decode", ciphertext: ciphertext, fn: malloryBoxer.Decode, expectErr: true},
				{name: "mallory cannot decode unverified", ciphertext: ciphertext, fn: malloryBoxer.DecodeUnverified, expectErr: true},
				{name: "bare mallory cannot decode", ciphertext: ciphertext, fn: bareMalloryBoxer.Decode, expectErr: true},
				{name: "bare mallory cannot decode unverified", ciphertext: ciphertext, fn: bareMalloryBoxer.DecodeUnverified, expectErr: true},
				{name: "bare alice cannot verify and decode", ciphertext: ciphertext, fn: bareAliceBoxer.Decode, expectErr: true},
			}

			for _, tf := range testFuncs {
				tf := tf

				t.Run(tf.name, func(t *testing.T) {
					t.Parallel()
					if tf.expectErr {
						box, err := tf.fn(tf.ciphertext)
						require.Error(t, err)
						require.Nil(t, box)
					} else {
						box, err := tf.fn(tf.ciphertext)
						require.NoError(t, err)
						require.Equal(t, message, box.Data(), "decoded matches")
					}
				})
			}
		})

		t.Run("go encrypt ruby decrypt", func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()

			responseTo := ulid.New()
			ciphertext, err := aliceBoxer.Encode(responseTo, message)
			require.NoError(t, err)

			var png bytes.Buffer
			pngFile := filepath.Join(dir, ulid.New()+".png")
			require.NoError(t, aliceBoxer.EncodePng(responseTo, message, &png))
			require.NoError(t, os.WriteFile(pngFile, png.Bytes(), 0644))

			tests := []boxerCrossTestCase{
				// Go encoded, ruby successfully decode
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKey.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(), Ciphertext: ciphertext, cmd: "decode"},
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKey.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},
				{Key: bobPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKey.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(), PngFile: pngFile, cmd: "decodepng"},

				// Cannot use decode method on png
				{Key: bobPem.Bytes(), PngFile: pngFile, cmd: "decode", expectErr: true},

				// No ciphertext. Should throw error
				{Key: bobPem.Bytes(), cmd: "decode", expectErr: true},

				// Go encoded, ruby cannot decode with wrong keys
				{Key: malloryPem.Bytes(), CounterpartySigningKey: alicePubSigningKey.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
				{Key: malloryPem.Bytes(), CounterpartySigningKey: alicePubSigningKey.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKey.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},
				{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
				{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},
			}

			for _, tt := range tests {
				tt := tt

				t.Run("", func(t *testing.T) {
					t.Parallel()

					if runtime.GOOS == "windows" && tt.cmd == "decodepng" {
						t.Skip("skip png decode test on windows because ruby library chunky_png is looking for CRLF png signature")
					}

					testfile := filepath.Join(dir, ulid.New()+".msgpack")
					rubyout := filepath.Join(dir, ulid.New()+"ruby-out")

					//
					// Setup
					//
					b, err := msgpack.Marshal(tt)
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

					ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
					defer cancel()

					//#nosec G204 -- No taint on hardcoded input
					cmd := exec.CommandContext(ctx, "ruby", boxerRB, tt.cmd, testfile, rubyout)
					out, err := cmd.CombinedOutput()

					require.NoError(t, ctx.Err())

					//
					// Check
					//
					if tt.expectErr {
						require.Error(t, err)
						return
					}

					require.NoError(t, err, string(out))

					rubyResult, err := os.ReadFile(rubyout)
					require.NoError(t, err)

					var actual boxerCrossTestCase
					require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &actual))

					require.Equal(t, message, actual.Plaintext, "plaintext matches")
				})
			}
		})

		t.Run("ruby sign, go verify", func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()

			var ciphertext string

			t.Run("ruby sign", func(t *testing.T) {
				rubyInFile := filepath.Join(dir, ulid.New()+".msgpack")
				rubyOutFile := filepath.Join(dir, ulid.New()+"ruby-out")

				rubyCommand := boxerCrossTestCase{
					Key:        bobPem.Bytes(),
					Plaintext:  message,
					ResponseTo: ulid.New(),
				}

				b, err := msgpack.Marshal(rubyCommand)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(rubyInFile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", boxerRB, "sign", rubyInFile, rubyOutFile)

				require.NoError(t, ctx.Err())

				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				rubyResult, err := os.ReadFile(rubyOutFile)
				require.NoError(t, err)

				var unpacked boxerCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &unpacked))

				require.NotEmpty(t, unpacked.Ciphertext)
				ciphertext = unpacked.Ciphertext
			})

			var testFuncs = []struct {
				name       string
				fn         func(string) (*krypto.Box, error)
				expectErr  bool
				ciphertext string
			}{

				{name: "alice can verify", ciphertext: ciphertext, fn: aliceBoxer.Decode},
				{name: "alice can verify unverified", ciphertext: ciphertext, fn: aliceBoxer.DecodeUnverified},
				{name: "bare alice can verify unverified", ciphertext: ciphertext, fn: bareAliceBoxer.DecodeUnverified},

				{name: "bare alice cannot verify", ciphertext: ciphertext, fn: bareAliceBoxer.Decode, expectErr: true},
			}

			for _, tf := range testFuncs {
				tf := tf
				t.Run(tf.name, func(t *testing.T) {
					t.Parallel()
					if tf.expectErr {
						box, err := tf.fn(tf.ciphertext)
						require.Error(t, err)
						require.Nil(t, box)
					} else {
						box, err := tf.fn(tf.ciphertext)
						require.NoError(t, err)
						require.Equal(t, message, box.Signedtext, "signed text matches")
					}
				})
			}
		})
	}
}

func TestTpmBoxerRuby(t *testing.T) { //nolint:paralleltest
	bobKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var bobPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(bobKey, &bobPem))

	malloryKey, err := krypto.RsaRandomKey()
	require.NoError(t, err)
	var malloryPem bytes.Buffer
	require.NoError(t, krypto.RsaPrivateKeyToPem(malloryKey, &malloryPem))

	tpmEncoder := testTpmEncoder(t)
	aliceBoxer := krypto.NewEncoderBoxer(tpmEncoder, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))

	var alicePubSigningKeyPem bytes.Buffer
	alicePubSigningKey, err := aliceBoxer.Encoder.PublicSigningKey()
	require.NoError(t, err)
	require.NoError(t, krypto.RsaPublicToPublicPem(alicePubSigningKey, &alicePubSigningKeyPem))

	var alicePubEncryptionKeyPem bytes.Buffer
	alicePubEncryptionKey, err := aliceBoxer.Encoder.PublicEncryptionKey()
	require.NoError(t, err)
	require.NoError(t, krypto.RsaPublicToPublicPem(alicePubEncryptionKey, &alicePubEncryptionKeyPem))

	bareAliceBoxer := krypto.NewEncoderBoxer(tpmEncoder, nil, nil)
	malloryBoxer := krypto.NewKeyBoxer(malloryKey, bobKey.Public().(*rsa.PublicKey), bobKey.Public().(*rsa.PublicKey))
	bareMalloryBoxer := krypto.NewKeyBoxer(malloryKey, nil, nil)

	testMessages := [][]byte{
		[]byte("a"),
		[]byte("Hello World"),
		[]byte("This isn't super long, but it's at least a little long?"),
		[]byte(randomString(t, 1024)),
		mkrand(t, 1024),
		[]byte(randomString(t, 4096)),
		mkrand(t, 4096),
	}

	// Ruby Decrypt Tests
	//#nosec G306 -- Need readable files
	for _, message := range testMessages {
		message := message

		t.Run("ruby encrypt go decrypt", func(t *testing.T) {
			var ciphertext string

			t.Run("ruby encrypt", func(t *testing.T) {
				dir := t.TempDir()
				rubyInFile := filepath.Join(dir, "testcase.msgpack")
				rubyOutFile := filepath.Join(dir, "ruby-out")

				rubyCommand := boxerCrossTestCase{
					Key:                       bobPem.Bytes(),
					CounterpartySigningKey:    alicePubSigningKeyPem.Bytes(),
					CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(),
					Plaintext:                 message,
					ResponseTo:                ulid.New(),
				}

				b, err := msgpack.Marshal(rubyCommand)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(rubyInFile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", boxerRB, "encode", rubyInFile, rubyOutFile)

				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err())
				require.NoError(t, err, string(out))

				rubyResult, err := os.ReadFile(rubyOutFile)
				require.NoError(t, err)

				var unpacked boxerCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &unpacked))

				require.NotEmpty(t, unpacked.Ciphertext)
				ciphertext = unpacked.Ciphertext
			})

			var testFuncs = []struct {
				name       string
				fn         func(string) (*krypto.Box, error)
				expectErr  bool
				ciphertext string
			}{
				{name: "alice can decode", ciphertext: ciphertext, fn: aliceBoxer.Decode},
				{name: "alice can decode unverified", ciphertext: ciphertext, fn: aliceBoxer.DecodeUnverified},
				{name: "bare alice can decode unverified", ciphertext: ciphertext, fn: bareAliceBoxer.DecodeUnverified},

				{name: "mallory cannot decode", ciphertext: ciphertext, fn: malloryBoxer.Decode, expectErr: true},
				{name: "mallory cannot decode unverified", ciphertext: ciphertext, fn: malloryBoxer.DecodeUnverified, expectErr: true},
				{name: "bare mallory cannot decode", ciphertext: ciphertext, fn: bareMalloryBoxer.Decode, expectErr: true},
				{name: "bare mallory cannot decode unverified", ciphertext: ciphertext, fn: bareMalloryBoxer.DecodeUnverified, expectErr: true},
				{name: "bare alice cannot verify and decode", ciphertext: ciphertext, fn: bareAliceBoxer.Decode, expectErr: true},
			}

			for _, tf := range testFuncs {
				tf := tf

				t.Run(tf.name, func(t *testing.T) {
					if tf.expectErr {
						box, err := tf.fn(tf.ciphertext)
						require.Error(t, err)
						require.Nil(t, box)
					} else {
						box, err := tf.fn(tf.ciphertext)
						require.NoError(t, err)
						require.Equal(t, message, box.Data(), "decoded matches")
					}
				})
			}
		})

		t.Run("go encrypt ruby decrypt", func(t *testing.T) {
			dir := t.TempDir()

			responseTo := ulid.New()
			ciphertext, err := aliceBoxer.Encode(responseTo, message)
			require.NoError(t, err)

			var png bytes.Buffer
			pngFile := filepath.Join(dir, ulid.New()+".png")
			require.NoError(t, aliceBoxer.EncodePng(responseTo, message, &png))
			require.NoError(t, os.WriteFile(pngFile, png.Bytes(), 0644))

			tests := []boxerCrossTestCase{
				// Go encoded, ruby successfully decode
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKeyPem.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(), Ciphertext: ciphertext, cmd: "decode"},
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKeyPem.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},
				{Key: bobPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified"},
				{Key: bobPem.Bytes(), CounterpartySigningKey: alicePubSigningKeyPem.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(), PngFile: pngFile, cmd: "decodepng"},

				// Cannot use decode method on png
				{Key: bobPem.Bytes(), PngFile: pngFile, cmd: "decode", expectErr: true},

				// No ciphertext. Should throw error
				{Key: bobPem.Bytes(), cmd: "decode", expectErr: true},

				// Go encoded, ruby cannot decode with wrong keys
				{Key: malloryPem.Bytes(), CounterpartySigningKey: alicePubSigningKeyPem.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
				{Key: malloryPem.Bytes(), CounterpartySigningKey: alicePubSigningKeyPem.Bytes(), CounterpartyEncryptionKey: alicePubEncryptionKeyPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},
				{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decode", expectErr: true},
				{Key: malloryPem.Bytes(), Ciphertext: ciphertext, cmd: "decodeunverified", expectErr: true},
			}

			for _, tt := range tests {
				tt := tt

				t.Run("", func(t *testing.T) {
					t.Parallel()

					if runtime.GOOS == "windows" && tt.cmd == "decodepng" {
						t.Skip("skip png decode test on windows because ruby library chunky_png is looking for CRLF png signature")
					}

					testfile := filepath.Join(dir, ulid.New()+".msgpack")
					rubyout := filepath.Join(dir, ulid.New()+"ruby-out")

					//
					// Setup
					//
					b, err := msgpack.Marshal(tt)
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(testfile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

					ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
					defer cancel()

					//#nosec G204 -- No taint on hardcoded input
					cmd := exec.CommandContext(ctx, "ruby", boxerRB, tt.cmd, testfile, rubyout)
					out, err := cmd.CombinedOutput()

					require.NoError(t, ctx.Err())

					//
					// Check
					//
					if tt.expectErr {
						require.Error(t, err)
						return
					}

					require.NoError(t, err, string(out))

					rubyResult, err := os.ReadFile(rubyout)
					require.NoError(t, err)

					var actual boxerCrossTestCase
					require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &actual))

					require.Equal(t, message, actual.Plaintext, "plaintext matches")
				})
			}
		})

		t.Run("ruby sign, go verify", func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			var ciphertext string

			t.Run("ruby sign", func(t *testing.T) {
				rubyInFile := filepath.Join(dir, ulid.New()+".msgpack")
				rubyOutFile := filepath.Join(dir, ulid.New()+"ruby-out")

				rubyCommand := boxerCrossTestCase{
					Key:        bobPem.Bytes(),
					Plaintext:  message,
					ResponseTo: ulid.New(),
				}

				b, err := msgpack.Marshal(rubyCommand)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(rubyInFile, []byte(base64.StdEncoding.EncodeToString(b)), 0644))

				ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
				defer cancel()

				cmd := exec.CommandContext(ctx, "ruby", boxerRB, "sign", rubyInFile, rubyOutFile)

				require.NoError(t, ctx.Err())

				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				rubyResult, err := os.ReadFile(rubyOutFile)
				require.NoError(t, err)

				var unpacked boxerCrossTestCase
				require.NoError(t, msgpack.Unmarshal(base64Decode(t, string(rubyResult)), &unpacked))

				require.NotEmpty(t, unpacked.Ciphertext)
				ciphertext = unpacked.Ciphertext
			})

			var testFuncs = []struct {
				name       string
				fn         func(string) (*krypto.Box, error)
				expectErr  bool
				ciphertext string
			}{

				{name: "alice can verify", ciphertext: ciphertext, fn: aliceBoxer.Decode},
				{name: "alice can verify unverified", ciphertext: ciphertext, fn: aliceBoxer.DecodeUnverified},
				{name: "bare alice can verify unverified", ciphertext: ciphertext, fn: bareAliceBoxer.DecodeUnverified},

				{name: "bare alice cannot verify", ciphertext: ciphertext, fn: bareAliceBoxer.Decode, expectErr: true},
			}

			for _, tf := range testFuncs {
				tf := tf
				t.Run(tf.name, func(t *testing.T) {
					if tf.expectErr {
						box, err := tf.fn(tf.ciphertext)
						require.Error(t, err)
						require.Nil(t, box)
					} else {
						box, err := tf.fn(tf.ciphertext)
						require.NoError(t, err)
						require.Equal(t, message, box.Signedtext, "signed text matches")
					}
				})
			}
		})
	}
}

func testTpmEncoder(t *testing.T) *krypto.TpmEncoder {
	tpmEncoder := &krypto.TpmEncoder{}
	tpm, err := tpmEncoder.OpenTpm()

	// have a working tpm
	if err == nil {
		t.Log("actual tpm found, using for tests")
		tpm.Close()
		return tpmEncoder
	}

	// no working tpm, use simulator
	t.Log("no tpm found, using simulator")
	simulatedTpm, err := simulator.Get()
	require.NoError(t, err)

	t.Cleanup(func() {
		CheckedClose(t, simulatedTpm)
	})

	tpmEncoder.ExternalTpm = simulatedTpm

	return tpmEncoder
}

// CheckedClose closes the simulator and asserts that there were no leaked handles.
func CheckedClose(t *testing.T, rwc io.ReadWriteCloser) {
	// modifed version of:
	// https://github.com/google/go-tpm-tools/blob/d27e86e31f40ddd8720bfbebc20cb2ceae30fddb/client/close.go#L11
	// thank you!

	for _, handle := range []tpm2.HandleType{
		tpm2.HandleTypeLoadedSession,
		tpm2.HandleTypeSavedSession,
		tpm2.HandleTypeTransient,
	} {
		handles, err := Handles(rwc, handle)
		require.NoError(t, err)
		require.Empty(t, len(handles), fmt.Sprintf("test leaked handles: %v", handles))
	}

	require.NoError(t, rwc.Close())
}

// Handles returns a slice of tpmutil.Handle objects of all handles within
// the TPM rw of type handleType.
func Handles(rw io.ReadWriter, handleType tpm2.HandleType) ([]tpmutil.Handle, error) {
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
