package krypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

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
