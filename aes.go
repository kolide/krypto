package krypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Ruby seems to support 2 modes for AES. There's an older CBC mode, this
// is not recommended but could be implemented with something similar to
// https://github.com/funny/crypto/blob/master/aes256cbc/aes256cbc.go
// or https://dequeue.blogspot.com/2014/11/decrypting-something-encrypted-with.html
// (Or even https://go.dev/src/crypto/cipher/example_test.go).
// However, much betteris to use GCM mode.
//
// There are some notable differences. Ruby returns the MAC (or auth_tag or auth data) seperately, where as the go library appends it. Easy enough to deal with.
// Some URLs I found helpful:
// - https://stackoverflow.com/questions/68040875/
// - https://stackoverflow.com/questions/68350301
// - https://crypto.stackexchange.com/questions/25249
// - https://pkg.go.dev/crypto/cipher

func AesEncrypt(key, authData, plaintext []byte) ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	return aesgcm.Seal(iv, iv, plaintext, authData), nil
}

func AesDecrypt(key, authData, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	ivSize := aesgcm.NonceSize()

	if len(ciphertext) < ivSize+1 {
		return nil, errors.New("ciphertext too short")
	}
	iv, cutCiphertext := ciphertext[:ivSize], ciphertext[ivSize:]

	return aesgcm.Open(nil, iv, cutCiphertext, authData)
}

func AesRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}
