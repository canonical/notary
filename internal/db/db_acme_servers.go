package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

func (db *DatabaseRepository) CreateACMEServer(name, directoryURL, email, dnsProvider string, envVars map[string]string) (int64, error) {
	encryptedEnvVars, err := encryptEnvVars(envVars, db.EncryptionKey)
	if err != nil {
		return 0, err
	}
	row := ACMEServer{
		Name:         name,
		DirectoryURL: directoryURL,
		Email:        email,
		DNSProvider:  dnsProvider,
		EnvVars:      encryptedEnvVars,
	}
	return CreateEntity[ACMEServer](db, db.stmts.CreateACMEServer, row)
}

func (db *DatabaseRepository) ListACMEServers() ([]ACMEServer, error) {
	return ListEntities[ACMEServer](db, db.stmts.ListACMEServers)
}

func (db *DatabaseRepository) GetACMEServer(id int64) (*ACMEServer, error) {
	row := ACMEServer{ID: id}
	return GetOneEntity[ACMEServer](db, db.stmts.GetACMEServer, row)
}

func (db *DatabaseRepository) GetDecryptedACMEServer(id int64) (*ACMEServer, error) {
	server, err := db.GetACMEServer(id)
	if err != nil {
		return nil, err
	}
	return decryptServerEnvVars(server, db.EncryptionKey)
}

func (db *DatabaseRepository) GetActiveACMEServer() (*ACMEServer, error) {
	return GetOneEntity[ACMEServer](db, db.stmts.GetActiveACMEServer)
}

func (db *DatabaseRepository) GetDecryptedActiveACMEServer() (*ACMEServer, error) {
	server, err := db.GetActiveACMEServer()
	if err != nil {
		return nil, err
	}
	return decryptServerEnvVars(server, db.EncryptionKey)
}

func (db *DatabaseRepository) UpdateACMEServer(id int64, name, directoryURL, email, dnsProvider string, envVars map[string]string) error {
	encryptedEnvVars, err := encryptEnvVars(envVars, db.EncryptionKey)
	if err != nil {
		return err
	}
	row := ACMEServer{
		ID:           id,
		Name:         name,
		DirectoryURL: directoryURL,
		Email:        email,
		DNSProvider:  dnsProvider,
		EnvVars:      encryptedEnvVars,
	}
	return UpdateEntity[ACMEServer](db, db.stmts.UpdateACMEServer, row)
}

// SetActiveACMEServer deactivates all servers then activates the given ID in a transaction.
func (db *DatabaseRepository) SetActiveACMEServer(id int64) error {
	tx, err := db.Conn.PlainDB().BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to set active ACME server: %w", ErrInternal)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec("UPDATE acme_servers SET active = 0"); err != nil {
		return fmt.Errorf("failed to deactivate ACME servers: %w", ErrInternal)
	}

	result, err := tx.Exec("UPDATE acme_servers SET active = 1 WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to activate ACME server: %w", ErrInternal)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to activate ACME server: %w", ErrInternal)
	}
	if affected == 0 {
		return fmt.Errorf("failed to activate ACME server: %w", ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to set active ACME server: %w", ErrInternal)
	}
	return nil
}

func (db *DatabaseRepository) DeleteACMEServer(id int64) error {
	row := ACMEServer{ID: id}
	return DeleteEntity[ACMEServer](db, db.stmts.DeleteACMEServer, row)
}

func encryptEnvVars(envVars map[string]string, key []byte) (string, error) {
	jsonBytes, err := json.Marshal(envVars)
	if err != nil {
		return "", fmt.Errorf("%w: failed to marshal env vars", ErrInternal)
	}
	encrypted, err := utils.Encrypt(string(jsonBytes), key)
	if err != nil {
		return "", fmt.Errorf("%w: failed to encrypt env vars", ErrInternal)
	}
	return encrypted, nil
}

func decryptServerEnvVars(server *ACMEServer, key []byte) (*ACMEServer, error) {
	decrypted, err := utils.Decrypt(server.EnvVars, key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt env vars", ErrInternal)
	}
	server.EnvVars = decrypted
	return server, nil
}
