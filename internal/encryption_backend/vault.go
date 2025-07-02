package encryption_backend

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"go.uber.org/zap"
)

const encryptionType = "aes256-gcm96"

// VaultBackend implements EncryptionBackend interface for Vault
type VaultBackend struct {
	client  *vault.Client
	mount   string
	keyName string
	logger  *zap.Logger
}

// Decrypt implements SecretBackend.
func (v VaultBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	return decryptData(v.client, v.mount, v.keyName, ciphertext)
}

// Encrypt implements SecretBackend.
func (v VaultBackend) Encrypt(plaintext []byte) ([]byte, error) {
	return encryptData(v.client, v.mount, v.keyName, plaintext)
}

func encryptData(client *vault.Client, mount string, keyName string, plaintext []byte) ([]byte, error) {
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	encryptRequest := schema.TransitEncryptRequest{
		Plaintext:  encodedPlaintext,
		Type:       encryptionType,
		KeyVersion: 0, // use the latest version of the key
	}
	// TODO: What context should we use here?
	encryptedResponse, err := client.Secrets.TransitEncrypt(context.Background(), keyName, encryptRequest, vault.WithMountPath(mount))
	if err != nil {
		return nil, err
	}
	return encryptedResponse.Data["ciphertext"].([]byte), nil
}

func decryptData(client *vault.Client, mount string, keyName string, ciphertext []byte) ([]byte, error) {
	// Vault expects the ciphertext to be a base64 encoded string
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	decryptRequest := schema.TransitDecryptRequest{
		Ciphertext: encodedCiphertext,
	}
	// TODO: What context should we use here?
	decryptedResponse, err := client.Secrets.TransitDecrypt(context.Background(), keyName, decryptRequest, vault.WithMountPath(mount))
	if err != nil {
		return nil, err
	}
	decodedPlaintext, err := base64.StdEncoding.DecodeString(decryptedResponse.Data["plaintext"].(string))
	if err != nil {
		return nil, err
	}
	return decodedPlaintext, nil
}

// Validate implements SecretBackend.
func NewVaultTokenBackend(endpoint string, mount string, keyName string, token string, logger *zap.Logger) (VaultBackend, error) {
	client, err := vault.New(
		vault.WithAddress(endpoint),
	)
	if err != nil {
		return VaultBackend{}, err
	}
	err = client.SetToken(token)
	if err != nil {
		return VaultBackend{}, err
	}
	backend := VaultBackend{
		client:  client,
		mount:   mount,
		keyName: keyName,
		logger:  logger,
	}
	return backend, nil
}

func NewVaultRoleBackend(endpoint string, mount string, keyName string, roleID string, roleSecretID string, logger *zap.Logger) (VaultBackend, error) {
	// TODO: What context should we use here?
	ctx := context.Background()
	client, err := vault.New(
		vault.WithAddress(endpoint),
	)
	if err != nil {
		return VaultBackend{}, err
	}

	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   roleID,
		SecretId: roleSecretID,
	})
	if err != nil {
		return VaultBackend{}, err
	}
	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		logger.Fatal("Error setting token", zap.Error(err))
	}
	backend := VaultBackend{
		client:  client,
		mount:   mount,
		keyName: keyName,
		logger:  logger,
	}
	return backend, nil
}
