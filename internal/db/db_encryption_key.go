// TODO yazan, we could simplify this following the JWT secret example
package db

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/canonical/sqlair"
)

type AES256GCMEncryptionKey struct {
	EncryptionKeyID int64  `db:"encryption_key_id"`
	EncryptionKey   string `db:"encryption_key"`
}

func (db *Database) GetEncryptionKey() ([]byte, error) {
	encryptionKey, err := ListEntities[AES256GCMEncryptionKey](db, db.stmts.GetEncryptionKey)
	if err != nil {
		return nil, err
	}
	if len(encryptionKey) == 0 {
		return nil, fmt.Errorf("%w: no encryption key found", ErrNotFound)
	}
	if len(encryptionKey) > 1 {
		return nil, fmt.Errorf("%w: multiple encryption keys found", ErrInternal)
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encryptionKey[0].EncryptionKey)
	if err != nil {
		return nil, err
	}
	return decodedKey, nil
}

func (db *Database) CreateEncryptionKey(encryptionKey []byte) error {
	key := AES256GCMEncryptionKey{
		EncryptionKey: base64.StdEncoding.EncodeToString(encryptionKey),
	}
	var outcome sqlair.Outcome
	err := db.conn.Query(context.Background(), db.stmts.CreateEncryptionKey, key).Get(&outcome)
	if err != nil {
		return err
	}
	_, err = outcome.Result().LastInsertId()
	if err != nil {
	}
	return nil
}

func (db *Database) DeleteEncryptionKey() error {
	encryptionKey, err := db.GetEncryptionKey()
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), db.stmts.DeleteEncryptionKey, encryptionKey).Get(&encryptionKey)
	if err != nil {
		return err
	}
	return nil
}
