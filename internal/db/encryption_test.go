package db

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "Simple string",
			input:     "hello world",
			wantError: false,
		},
		{
			name:      "Empty string",
			input:     "",
			wantError: false,
		},
		{
			name:      "Long string",
			input:     strings.Repeat("long text ", 100),
			wantError: false,
		},
		{
			name:      "Special characters",
			input:     "!@#$%^&*()_+-=[]{}|;:,.<>?",
			wantError: false,
		},
		{
			name:      "Unicode characters",
			input:     "Hello 世界 🌍",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := Encrypt(tt.input, key)
			if (err != nil) != tt.wantError {
				t.Errorf("Encrypt() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if tt.wantError {
				return
			}

			// Verify encrypted string is not the same as input
			if encrypted == tt.input {
				t.Errorf("Encrypted text matches input text")
			}

			// Decrypt
			decrypted, err := Decrypt(encrypted, key)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			// Compare
			if decrypted != tt.input {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.input)
			}
		})
	}
}

func TestEncryptionKeySize(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		wantError bool
	}{
		{
			name:      "Valid 32-byte key",
			keySize:   32,
			wantError: false,
		},
		{
			name:      "Invalid 16-byte key",
			keySize:   16,
			wantError: true,
		},
		{
			name:      "Invalid empty key",
			keySize:   0,
			wantError: true,
		},
		{
			name:      "Invalid 24-byte key",
			keySize:   24,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if tt.keySize > 0 {
				if _, err := rand.Read(key); err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
			}

			_, err := Encrypt("test", key)
			if (err != nil) != tt.wantError {
				t.Errorf("Encrypt() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestDecryptionErrors(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	// Create a valid encrypted string
	validEncrypted, err := Encrypt("test", key)
	if err != nil {
		t.Fatalf("Failed to create valid encrypted string: %v", err)
	}

	tests := []struct {
		name            string
		encryptedString string
		key             []byte
		wantError       bool
	}{
		{
			name:            "Valid decryption",
			encryptedString: validEncrypted,
			key:             key,
			wantError:       false,
		},
		{
			name:            "Wrong key",
			encryptedString: validEncrypted,
			key:             wrongKey,
			wantError:       true,
		},
		{
			name:            "Invalid base64",
			encryptedString: "not-base64",
			key:             key,
			wantError:       true,
		},
		{
			name:            "Empty string",
			encryptedString: "",
			key:             key,
			wantError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.encryptedString, tt.key)
			if (err != nil) != tt.wantError {
				t.Errorf("Decrypt() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
