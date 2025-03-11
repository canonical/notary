package db

import (
	"context"
	"errors"
	"fmt"
	"log"

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
	return ListEntities[PrivateKey](db, listPrivateKeysStmt)
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
		return nil, InvalidFilterError("private key", "both ID and PEM are nil")
	}

	return GetOneEntity(db, getPrivateKeyStmt, pkRow)
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		log.Println(err)
		return 0, errors.New("Invalid private key: " + err.Error())
	}
	stmt, err := sqlair.Prepare(createPrivateKeyStmt, PrivateKey{})
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create private key", ErrInternal)
	}
	row := PrivateKey{
		PrivateKeyPEM: pk,
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, row).Get(&outcome)
	if err != nil {
		log.Println(err)
		if isUniqueConstraintError(err) {
			return 0, fmt.Errorf("%w: private key already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create private key", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create private key", ErrInternal)
	}
	return insertedRowID, nil
}

// DeletePrivateKey deletes a private key from the database.
func (db *Database) DeletePrivateKey(filter PrivateKeyFilter) error {
	var pkRow PrivateKey

	switch {
	case filter.ID != nil:
		pkRow = PrivateKey{PrivateKeyID: *filter.ID}
	case filter.PEM != nil:
		pkRow = PrivateKey{PrivateKeyPEM: *filter.PEM}
	default:
		return InvalidFilterError("private key", "both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(deletePrivateKeyStmt, PrivateKey{})
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to prepare delete private key statement", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Run()
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to delete private key", ErrInternal)
	}
	return nil
}
