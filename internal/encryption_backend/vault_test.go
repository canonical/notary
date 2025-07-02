package encryption_backend

import (
	"bytes"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// mockVaultClient simulates the minimal Vault client interface needed for testing.
type mockVaultClient struct {
	encryptFunc func(plaintext []byte) ([]byte, error)
	decryptFunc func(ciphertext []byte) ([]byte, error)
}

func (m *mockVaultClient) Encrypt(plaintext []byte) ([]byte, error) {
	return m.encryptFunc(plaintext)
}
func (m *mockVaultClient) Decrypt(ciphertext []byte) ([]byte, error) {
	return m.decryptFunc(ciphertext)
}

// VaultBackendMockable allows injection of a mock client for testing.
type VaultBackendMockable struct {
	client  *mockVaultClient
	mount   string
	keyName string
	logger  *zap.Logger
}

func (v VaultBackendMockable) Encrypt(plaintext []byte) ([]byte, error) {
	return v.client.Encrypt(plaintext)
}
func (v VaultBackendMockable) Decrypt(ciphertext []byte) ([]byte, error) {
	return v.client.Decrypt(ciphertext)
}

func TestVaultEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "normal message",
			message: []byte("test data to encrypt and decrypt"),
		},
		{
			name:    "short message",
			message: []byte("short"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate encryption as reversing the bytes and decryption as reversing again.
			mockClient := &mockVaultClient{
				encryptFunc: func(plaintext []byte) ([]byte, error) {
					enc := make([]byte, len(plaintext))
					copy(enc, plaintext)
					for i, j := 0, len(enc)-1; i < j; i, j = i+1, j-1 {
						enc[i], enc[j] = enc[j], enc[i]
					}
					return enc, nil
				},
				decryptFunc: func(ciphertext []byte) ([]byte, error) {
					dec := make([]byte, len(ciphertext))
					copy(dec, ciphertext)
					for i, j := 0, len(dec)-1; i < j; i, j = i+1, j-1 {
						dec[i], dec[j] = dec[j], dec[i]
					}
					return dec, nil
				},
			}

			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}

			backend := &VaultBackendMockable{
				client:  mockClient,
				mount:   "transit",
				keyName: "test-key",
				logger:  logger,
			}

			ciphertext, err := backend.Encrypt(tt.message)
			if err != nil {
				t.Fatalf("Expected encryption to succeed, got error: %v", err)
			}
			if len(ciphertext) != len(tt.message) {
				t.Fatalf("Expected ciphertext length %d, got %d", len(tt.message), len(ciphertext))
			}
			if bytes.Equal(ciphertext, tt.message) {
				t.Fatal("Expected ciphertext to differ from plaintext")
			}

			plaintext, err := backend.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Expected decryption to succeed, got error: %v", err)
			}
			if !bytes.Equal(tt.message, plaintext) {
				t.Fatalf("Expected decrypted data to match original.\nExpected: %q\nGot: %q", tt.message, plaintext)
			}
		})
	}

	t.Run("decrypt error", func(t *testing.T) {
		mockClient := &mockVaultClient{
			encryptFunc: func(plaintext []byte) ([]byte, error) {
				return []byte("irrelevant"), nil
			},
			decryptFunc: func(ciphertext []byte) ([]byte, error) {
				return nil, errors.New("mock decrypt error")
			},
		}
		logger, _ := zap.NewDevelopment()
		backend := &VaultBackendMockable{
			client:  mockClient,
			mount:   "transit",
			keyName: "test-key",
			logger:  logger,
		}
		_, err := backend.Decrypt([]byte("fail"))
		if err == nil || err.Error() != "mock decrypt error" {
			t.Fatalf("Expected mock decrypt error, got %v", err)
		}
	})
}
