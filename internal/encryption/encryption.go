package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Encrypt encrypts a string using AES-256-GCM.
// The key must be 32 bytes (256 bits) long.
// Returns base64-encoded encrypted string.
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key size: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := gcm.Seal(nonce, nonce, plaintextBytes, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded encrypted string using AES-256-GCM.
// The key must be the same 32-byte key used for encryption.
func Decrypt(encryptedString string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key size: must be 32 bytes for AES-256")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBody := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintextBytes, err := gcm.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintextBytes), nil
}

func GenerateAES256GCMEncryptionKey() (encryptionKey []byte, err error) {
	encryptionKey = make([]byte, 32) // 256 bits
	_, err = rand.Read(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random keys: %w", err)
	}

	return encryptionKey, nil
}
