package db

import (
	"encoding/base64"
	"fmt"
)

// GetEncryptionKey retrieves the only encryption key from the database.
func (db *Database) GetEncryptionKey() ([]byte, error) {
	encryptionKeyRow := AES256GCMEncryptionKey{
		EncryptionKeyID: 1,
	}
	encryptionKey, err := GetOneEntity[AES256GCMEncryptionKey](db, db.stmts.GetEncryptionKey, encryptionKeyRow)
	if err != nil {
		return nil, err
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
	_, err := CreateEntity[AES256GCMEncryptionKey](db, db.stmts.CreateEncryptionKey, key)
	return err
}

// DeleteEncryptionKey deletes the only encryption key from the database.
func (db *Database) DeleteEncryptionKey() error {
	return DeleteEntity[AES256GCMEncryptionKey](db, db.stmts.DeleteEncryptionKey, AES256GCMEncryptionKey{EncryptionKeyID: 1})
}
