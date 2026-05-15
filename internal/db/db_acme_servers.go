package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

// CreateACMEServer JSON-encodes and encrypts envVars, then inserts a new ACME server row.
// Returns the ID of the new row.
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

// ListACMEServers returns all ACME server rows. EnvVars is returned in its encrypted form.
func (db *DatabaseRepository) ListACMEServers() ([]ACMEServer, error) {
	return ListEntities[ACMEServer](db, db.stmts.ListACMEServers)
}

// GetACMEServer fetches a server by ID. EnvVars is returned in its encrypted form.
func (db *DatabaseRepository) GetACMEServer(id int64) (*ACMEServer, error) {
	row := ACMEServer{ID: id}
	return GetOneEntity[ACMEServer](db, db.stmts.GetACMEServer, row)
}

// GetDecryptedACMEServer fetches a server by ID and decrypts its EnvVars JSON.
func (db *DatabaseRepository) GetDecryptedACMEServer(id int64) (*ACMEServer, error) {
	server, err := db.GetACMEServer(id)
	if err != nil {
		return nil, err
	}
	return decryptServerEnvVars(server, db.EncryptionKey)
}

// GetActiveACMEServer returns the server row where active=1. Returns ErrNotFound if none is active.
func (db *DatabaseRepository) GetActiveACMEServer() (*ACMEServer, error) {
	return GetOneEntity[ACMEServer](db, db.stmts.GetActiveACMEServer)
}

// GetDecryptedActiveACMEServer returns the active server with decrypted EnvVars.
func (db *DatabaseRepository) GetDecryptedActiveACMEServer() (*ACMEServer, error) {
	server, err := db.GetActiveACMEServer()
	if err != nil {
		return nil, err
	}
	return decryptServerEnvVars(server, db.EncryptionKey)
}

// UpdateACMEServer JSON-encodes and encrypts envVars, then updates the server row.
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

// SetActiveACMEServer deactivates all servers then activates the one with the given ID.
// Runs in a single transaction.
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

// DeleteACMEServer removes the server row with the given ID.
func (db *DatabaseRepository) DeleteACMEServer(id int64) error {
	row := ACMEServer{ID: id}
	return DeleteEntity[ACMEServer](db, db.stmts.DeleteACMEServer, row)
}

// encryptEnvVars JSON-encodes a map and encrypts the result.
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

// decryptServerEnvVars decrypts the EnvVars field of an ACMEServer and stores the result as a JSON string.
func decryptServerEnvVars(server *ACMEServer, key []byte) (*ACMEServer, error) {
	decrypted, err := utils.Decrypt(server.EnvVars, key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt env vars", ErrInternal)
	}
	server.EnvVars = decrypted
	return server, nil
}
