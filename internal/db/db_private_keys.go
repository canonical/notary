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

const queryCreatePrivateKeysTable = `
	CREATE TABLE IF NOT EXISTS private_keys (
	    private_key_id INTEGER PRIMARY KEY AUTOINCREMENT,

		private_key TEXT NOT NULL UNIQUE
)
`

const (
	listPrivateKeysStmt  = "SELECT &PrivateKey.* FROM private_keys"
	getPrivateKeyStmt    = "SELECT &PrivateKey.* FROM private_keys WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"
	createPrivateKeyStmt = "INSERT INTO private_keys (private_key) VALUES ($PrivateKey.private_key)"
	deletePrivateKeyStmt = "DELETE FROM private_keys WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"
)

// ListPrivateKeys gets every PrivateKey entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	privateKeys, err := ListEntities[PrivateKey](db, listPrivateKeysStmt)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list private keys", err)
	}
	return privateKeys, nil
}

// GetPrivateKey gets a private key row from the repository from a given ID or PEM.
func (db *Database) GetPrivateKey(filter PrivateKeyFilter) (*PrivateKey, error) {
	var pkRow PrivateKey

	switch {
	case filter.ID != nil:
		pkRow = PrivateKey{PrivateKeyID: *filter.ID}
	case filter.PEM != nil:
		pkRow = PrivateKey{PrivateKeyPEM: *filter.PEM}
	default:
		return nil, fmt.Errorf("%w: private key - both ID and PEM are nil", ErrInvalidFilter)
	}

	pk, err := GetOneEntity[PrivateKey](db, getPrivateKeyStmt, pkRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "private key")
		}
		return nil, fmt.Errorf("%w: failed to get private key", err)
	}
	return pk, nil
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		return 0, errors.New("Invalid private key: " + err.Error())
	}
	stmt, err := sqlair.Prepare(createPrivateKeyStmt, PrivateKey{})
	if err != nil {
		return 0, fmt.Errorf("%w: failed to create private key due to sql compilation error", ErrInternal)
	}
	row := PrivateKey{
		PrivateKeyPEM: pk,
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, row).Get(&outcome)
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

	stmt, err := sqlair.Prepare(deletePrivateKeyStmt, PrivateKey{})
	if err != nil {
		return fmt.Errorf("%w: failed to delete private key due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete private key", ErrInternal)
	}
	return nil
}
