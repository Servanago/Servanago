// Package secretbox seals small secrets (TOTP seeds) at rest with AES-256-GCM.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

var aad = []byte("servanago/totp/v1")

func gcm(secret string) (cipher.AEAD, error) {
	if secret == "" {
		return nil, errors.New("secretbox: empty key")
	}
	k, err := hkdf.Key(sha256.New, []byte(secret), nil, string(aad), 32)
	if err != nil {
		return nil, fmt.Errorf("secretbox: derive key: %w", err)
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return cipher.NewGCM(b)
}

// Seal returns nonce||ciphertext.
func Seal(secret string, plain []byte) ([]byte, error) {
	g, err := gcm(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secretbox: nonce: %w", err)
	}
	return g.Seal(nonce, nonce, plain, aad), nil
}

// Open reverses Seal; a wrong key or modified blob is an error.
func Open(secret string, blob []byte) ([]byte, error) {
	g, err := gcm(secret)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("secretbox: blob too short")
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("secretbox: cannot decrypt (wrong SERVANAGO_SECRET_KEY or corrupted data)")
	}
	return plain, nil
}
