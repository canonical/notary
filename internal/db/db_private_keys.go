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
	stmt, err := sqlair.Prepare(listPrivateKeysStmt, PrivateKey{})
	if err != nil {
		return nil, err
	}
	var privateKeys []PrivateKey
	err = db.conn.Query(context.Background(), stmt).GetAll(&privateKeys)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return privateKeys, nil
		}
		return nil, err
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
		return nil, fmt.Errorf("invalid filter identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(getPrivateKeyStmt, PrivateKey{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Get(&pkRow)
	if err != nil {
		return nil, err
	}
	return &pkRow, nil
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) error {
	if err := ValidatePrivateKey(pk); err != nil {
		return errors.New("private key validation failed: " + err.Error())
	}
	stmt, err := sqlair.Prepare(createPrivateKeyStmt, PrivateKey{})
	if err != nil {
		return err
	}
	row := PrivateKey{
		PrivateKeyPEM: pk,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
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
		return fmt.Errorf("invalid filter identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(deletePrivateKeyStmt, PrivateKey{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Run()
	if err != nil {
		return err
	}
	return nil
}
