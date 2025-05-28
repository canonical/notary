package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type PrivateKey struct {
	PrivateKeyID int64 `db:"private_key_id"`

	PrivateKeyPEM string `db:"private_key"`
}

// ListPrivateKeys gets every PrivateKey entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	privateKeys, err := ListEntities[PrivateKey](db, db.stmts.ListPrivateKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list private keys", err)
	}
	for i := range privateKeys {
		decryptedPK, err := Decrypt(privateKeys[i].PrivateKeyPEM, db.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decrypt private key", err)
		}
		privateKeys[i].PrivateKeyPEM = decryptedPK
	}
	return privateKeys, nil
}

// GetPrivateKey gets a private key row from the repository from a given ID or PEM.
func (db *Database) GetPrivateKey(filter PrivateKeyFilter) (*PrivateKey, error) {
	var pkRow PrivateKey

	switch {
	case filter.ID != nil:
		pkRow = PrivateKey{PrivateKeyID: *filter.ID}
	default:
		return nil, fmt.Errorf("%w: private key - both ID and PEM are nil", ErrInvalidFilter)
	}
	pk, err := GetOneEntity[PrivateKey](db, db.stmts.GetPrivateKey, pkRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "private key")
		}
		return nil, fmt.Errorf("%w: failed to get private key", err)
	}
	decryptedPK, err := Decrypt(pk.PrivateKeyPEM, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt private key", err)
	}
	pk.PrivateKeyPEM = decryptedPK
	return pk, nil
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		return 0, errors.New("Invalid private key: " + err.Error())
	}
	encryptedPK, err := Encrypt(pk, db.EncryptionKey)
	row := PrivateKey{
		PrivateKeyPEM: encryptedPK,
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), db.stmts.CreatePrivateKey, row).Get(&outcome)
	if err != nil {
		if IsConstraintError(err, "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: private key already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create private key", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%w: failed to create private key", ErrInternal)
	}
	return insertedRowID, nil
}

// DeletePrivateKey deletes a private key from the database.
func (db *Database) DeletePrivateKey(filter PrivateKeyFilter) error {
	pkRow, err := db.GetPrivateKey(filter)
	if err != nil {
		return err
	}

	err = db.conn.Query(context.Background(), db.stmts.DeletePrivateKey, pkRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete private key", ErrInternal)
	}
	return nil
}
