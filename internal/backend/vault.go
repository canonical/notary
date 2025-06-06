package backend

import (
	"context"
	"encoding/base64"
	"log"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

const encryptionType = "aes256-gcm96"

type VaultBackend struct {
	client  *vault.Client
	mount   string
	keyName string
}

// Decrypt implements SecretBackend.
func (v VaultBackend) Decrypt(ciphertext string) (string, error) {
	return decryptData(v.client, v.mount, v.keyName, ciphertext)
}

// Encrypt implements SecretBackend.
func (v VaultBackend) Encrypt(plaintext string) (string, error) {
	return encryptData(v.client, v.mount, v.keyName, plaintext)
}

func encryptData(client *vault.Client, mount string, keyName, plaintext string) (string, error) {
	encodedPlaintext := base64.StdEncoding.EncodeToString([]byte(plaintext))

	encryptRequest := schema.TransitEncryptRequest{
		Plaintext:  encodedPlaintext,
		Type:       encryptionType,
		KeyVersion: 0, // use the latest version of the key
	}
	encryptedResponse, err := client.Secrets.TransitEncrypt(context.Background(), keyName, encryptRequest, vault.WithMountPath(mountPath))
	if err != nil {
		return "", err
	}
	return encryptedResponse.Data["ciphertext"].(string), nil
}

func decryptData(client *vault.Client, mount string, keyName, ciphertext string) (string, error) {
	decryptRequest := schema.TransitDecryptRequest{
		Ciphertext: ciphertext,
	}
	decryptedResponse, err := client.Secrets.TransitDecrypt(context.Background(), keyName, decryptRequest, vault.WithMountPath(mountPath))
	if err != nil {
		return "", err
	}
	decodedPlaintext, err := base64.StdEncoding.DecodeString(decryptedResponse.Data["plaintext"].(string))
	if err != nil {
		return "", err
	}
	return string(decodedPlaintext), nil
}

// Validate implements SecretBackend.
func NewVaultTokenBackend(endpoint string, mount string, keyName string, token string) (VaultBackend, error) {
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
	}
	return backend, nil
}

func NewVaultRoleBackend(endpoint string, mount string, keyName string, roleID string, roleSecretID string) (VaultBackend, error) {
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
		//FIXME: Use the proper logger here
		log.Fatal(err)
	}
	backend := VaultBackend{
		client:  client,
		mount:   mount,
		keyName: keyName,
	}
	return backend, nil
}
