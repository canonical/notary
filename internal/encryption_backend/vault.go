package encryption_backend

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"go.uber.org/zap"
)

const encryptionType = "aes256-gcm96"

type VaultSecretsProvider interface {
	TransitEncrypt(ctx context.Context, name string, request schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error)
	TransitDecrypt(ctx context.Context, name string, request schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error)
}

type VaultAuthProvider interface {
	AppRoleLogin(ctx context.Context, req schema.AppRoleLoginRequest, options ...vault.RequestOption) (*vault.Response[map[string]interface{}], error)
}

// VaultSecrets implements VaultSecretsProvider
type VaultSecrets struct {
	Secrets *vault.Secrets
}

func (s VaultSecrets) TransitEncrypt(ctx context.Context, name string, request schema.TransitEncryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
	return s.Secrets.TransitEncrypt(ctx, name, request, options...)
}
func (s VaultSecrets) TransitDecrypt(ctx context.Context, name string, request schema.TransitDecryptRequest, options ...vault.RequestOption) (*vault.Response[map[string]any], error) {
	return s.Secrets.TransitDecrypt(ctx, name, request, options...)
}

// VaultAuth implements VaultAuthProvider
type VaultAuth struct {
	Auth *vault.Auth
}

func (a VaultAuth) AppRoleLogin(ctx context.Context, req schema.AppRoleLoginRequest, options ...vault.RequestOption) (*vault.Response[map[string]interface{}], error) {
	return a.Auth.AppRoleLogin(ctx, req, options...)
}

type VaultClient struct {
	Auth    VaultAuthProvider
	Secrets VaultSecretsProvider
}

// VaultBackend implements EncryptionBackend interface for Vault
type VaultBackend struct {
	client  VaultClient
	mount   string
	keyName string
	logger  *zap.Logger
}

// Decrypt implements SecretBackend.
func (v VaultBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	// Vault expects the ciphertext to be a base64 encoded string
	ciphertextString := string(ciphertext)

	decryptRequest := schema.TransitDecryptRequest{
		Ciphertext: ciphertextString,
	}
	decryptedResponse, err := v.client.Secrets.TransitDecrypt(context.Background(), v.keyName, decryptRequest, vault.WithMountPath(v.mount))
	if err != nil {
		return nil, err
	}
	decodedPlaintext, err := base64.StdEncoding.DecodeString(decryptedResponse.Data["plaintext"].(string))
	if err != nil {
		return nil, err
	}
	return decodedPlaintext, nil
}

// Encrypt implements SecretBackend.
func (v VaultBackend) Encrypt(plaintext []byte) ([]byte, error) {
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	encryptRequest := schema.TransitEncryptRequest{
		Plaintext:  encodedPlaintext,
		Type:       encryptionType,
		KeyVersion: 0, // use the latest version of the key
	}
	encryptedResponse, err := v.client.Secrets.TransitEncrypt(context.Background(), v.keyName, encryptRequest, vault.WithMountPath(v.mount))
	if err != nil {
		return nil, err
	}
	return []byte(encryptedResponse.Data["ciphertext"].(string)), nil
}

// NewVaultBackendWithToken creates a new VaultBackend using token authentication.
func NewVaultBackendWithToken(endpoint, mount, keyName, token, tlsCaCertificate string, tlsSkipVerify bool, logger *zap.Logger) (VaultBackend, error) {
	logger.Info("Creating Vault backend", zap.String("endpoint", endpoint), zap.String("mount", mount), zap.String("keyName", keyName), zap.Bool("tls_skip_verify", tlsSkipVerify), zap.String("tls_ca_certificate", tlsCaCertificate))
	client, err := vault.New(
		vault.WithAddress(endpoint),
		vault.WithTLS(vault.TLSConfiguration{
			ServerCertificate:  vault.ServerCertificateEntry{FromFile: tlsCaCertificate},
			InsecureSkipVerify: tlsSkipVerify,
		}),
	)
	if err != nil {
		return VaultBackend{}, err
	}
	err = client.SetToken(token)
	if err != nil {
		return VaultBackend{}, err
	}
	backend := VaultBackend{
		client:  VaultClient{Auth: &client.Auth, Secrets: &client.Secrets},
		mount:   mount,
		keyName: keyName,
		logger:  logger,
	}
	return backend, nil
}

// NewVaultBackendWithAppRole creates a new VaultBackend using AppRole authentication.
func NewVaultBackendWithAppRole(endpoint, mount, keyName, roleID, roleSecretID, tlsCaCertificate string, tlsSkipVerify bool, logger *zap.Logger) (VaultBackend, error) {
	client, err := vault.New(
		vault.WithAddress(endpoint),
		vault.WithTLS(vault.TLSConfiguration{
			ServerCertificate:  vault.ServerCertificateEntry{FromFile: tlsCaCertificate},
			InsecureSkipVerify: tlsSkipVerify,
		}),
	)
	if err != nil {
		return VaultBackend{}, err
	}

	resp, err := client.Auth.AppRoleLogin(context.Background(), schema.AppRoleLoginRequest{
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
		client:  VaultClient{Auth: &client.Auth, Secrets: &client.Secrets},
		mount:   mount,
		keyName: keyName,
		logger:  logger,
	}
	return backend, nil
}
