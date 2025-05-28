package db

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type AES256GCMEncryptionKey struct {
	EncryptionKeyID int64  `db:"encryption_key_id"`
	EncryptionKey   string `db:"encryption_key"`
}

// GetEncryptionKey retrieves the only encryption key from the database.
func (db *Database) GetEncryptionKey() ([]byte, error) {
	encryptionKeyRow := AES256GCMEncryptionKey{
		EncryptionKeyID: 1,
	}
	encryptionKey, err := GetOneEntity[AES256GCMEncryptionKey](db, db.stmts.GetEncryptionKey, encryptionKeyRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: no encryption key found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encryptionKey.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode encryption key", ErrInternal)
	}
	return decodedKey, nil
}

// CreateEncryptionKey creates a new encryption key in the database, there can only be one encryption key.
func (db *Database) CreateEncryptionKey(encryptionKey []byte) error {
	key := AES256GCMEncryptionKey{
		EncryptionKey:   base64.StdEncoding.EncodeToString(encryptionKey),
		EncryptionKeyID: 1,
	}
	currentKey, err := db.GetEncryptionKey()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: failed to check if encryption key already exists", ErrInternal)
	}
	if currentKey != nil {
		return fmt.Errorf("%w: Encryption key already exists", ErrAlreadyExists)
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), db.stmts.CreateEncryptionKey, key).Get(&outcome)
	if err != nil {
		return fmt.Errorf("%w: failed to create encryption key", ErrInternal)
	}
	_, err = outcome.Result().LastInsertId()
	if err != nil {
		return fmt.Errorf("%w: failed to create encryption key", ErrInternal)
	}
	return nil
}

// DeleteEncryptionKey deletes the only encryption key from the database.
func (db *Database) DeleteEncryptionKey() error {
	_, err := db.GetEncryptionKey()
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), db.stmts.DeleteEncryptionKey, AES256GCMEncryptionKey{EncryptionKeyID: 1}).Run()
	if err != nil {
		return fmt.Errorf("failed to delete encryption key: %w", ErrInternal)
	}
	return nil
}
