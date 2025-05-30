package db_test

import (
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestEncryptDecryptEndToEnd(t *testing.T) {
	// Generate a random 32-byte key
	key, err := db.GenerateAES256GCMEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := "Hello, world!"
	encrypted, err := db.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := db.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypted text does not match original text")
	}
	_, err = db.Encrypt(plaintext, []byte("Invalid key"))
	if err == nil {
		t.Fatalf("Expected an error when encrypting with an invalid key, got nil")
	}
	_, err = db.Decrypt(encrypted, []byte("Invalid key"))
	if err == nil {
		t.Fatalf("Expected an error when decrypting with an invalid key, got nil")
	}
	encrypted2, err := db.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if encrypted == encrypted2 {
		t.Fatalf("Expected encrypted text to be different when encrypted multiple times")
	}
}
