package encryption_backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type mockVaultSecrets struct {
	encryptFunc func(ctx context.Context, name string, req schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error)
	decryptFunc func(ctx context.Context, name string, req schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error)
}

func (m *mockVaultSecrets) TransitEncrypt(ctx context.Context, name string, req schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
	return m.encryptFunc(ctx, name, req, options...)
}
func (m *mockVaultSecrets) TransitDecrypt(ctx context.Context, name string, req schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
	return m.decryptFunc(ctx, name, req, options...)
}

func TestVaultBackend_Encrypt_Success(t *testing.T) {
	plaintext := []byte("vault test")
	encoded := base64.StdEncoding.EncodeToString(plaintext)
	expectedCipher := "vault:v1:abcdef"

	mockSecrets := &mockVaultSecrets{
		encryptFunc: func(ctx context.Context, name string, req schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
			if req.Plaintext != encoded {
				t.Fatalf("Expected plaintext %q, got %q", encoded, req.Plaintext)
			}
			return &vault.Response[map[string]any]{Data: map[string]any{"ciphertext": expectedCipher}}, nil
		},
	}
	backend := VaultBackend{
		client:  VaultClient{Secrets: mockSecrets},
		mount:   "mount",
		keyName: "key",
	}

	ciphertext, err := backend.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if string(ciphertext) != expectedCipher {
		t.Fatalf("Expected ciphertext %q, got %q", expectedCipher, ciphertext)
	}
}

func TestVaultBackend_Encrypt_Error(t *testing.T) {
	mockSecrets := &mockVaultSecrets{
		encryptFunc: func(ctx context.Context, name string, req schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
			return nil, errors.New("encrypt error")
		},
	}
	backend := VaultBackend{
		client:  VaultClient{Secrets: mockSecrets},
		mount:   "mount",
		keyName: "key",
	}

	_, err := backend.Encrypt([]byte("fail"))
	if err == nil || err.Error() != "encrypt error" {
		t.Fatalf("Expected encrypt error, got %v", err)
	}
}

func TestVaultBackend_Decrypt_Success(t *testing.T) {
	expectedPlaintext := []byte("vault test")
	encoded := base64.StdEncoding.EncodeToString(expectedPlaintext)
	ciphertext := "vault:v1:abcdef"

	mockSecrets := &mockVaultSecrets{
		decryptFunc: func(ctx context.Context, name string, req schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
			if req.Ciphertext != ciphertext {
				t.Fatalf("Expected ciphertext %q, got %q", ciphertext, req.Ciphertext)
			}
			return &vault.Response[map[string]any]{Data: map[string]any{"plaintext": encoded}}, nil
		},
	}
	backend := VaultBackend{
		client:  VaultClient{Secrets: mockSecrets},
		mount:   "mount",
		keyName: "key",
	}

	plaintext, err := backend.Decrypt([]byte(ciphertext))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !bytes.Equal(plaintext, expectedPlaintext) {
		t.Fatalf("Expected plaintext %q, got %q", expectedPlaintext, plaintext)
	}
}

func TestVaultBackend_Decrypt_Error(t *testing.T) {
	mockSecrets := &mockVaultSecrets{
		decryptFunc: func(ctx context.Context, name string, req schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
			return nil, errors.New("decrypt error")
		},
	}
	backend := VaultBackend{
		client:  VaultClient{Secrets: mockSecrets},
		mount:   "mount",
		keyName: "key",
	}

	_, err := backend.Decrypt([]byte("fail"))
	if err == nil || err.Error() != "decrypt error" {
		t.Fatalf("Expected decrypt error, got %v", err)
	}
}

func TestVaultBackend_Decrypt_Base64Error(t *testing.T) {
	mockSecrets := &mockVaultSecrets{
		decryptFunc: func(ctx context.Context, name string, req schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
			return &vault.Response[map[string]any]{Data: map[string]any{"plaintext": "!!!notbase64!!!"}}, nil
		},
	}
	backend := VaultBackend{
		client:  VaultClient{Secrets: mockSecrets},
		mount:   "mount",
		keyName: "key",
	}

	_, err := backend.Decrypt([]byte("irrelevant"))
	if err == nil {
		t.Fatal("Expected base64 decode error, got nil")
	}
}
