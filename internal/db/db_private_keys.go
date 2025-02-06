package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type PrivateKey struct {
	PrivateKeyID int `db:"private_key_id"`

	PrivateKeyPEM string `db:"private_key"`
}

const queryCreatePrivateKeysTable = `
	CREATE TABLE IF NOT EXISTS %s (
	    private_key_id INTEGER PRIMARY KEY AUTOINCREMENT,

		private_key TEXT NOT NULL UNIQUE
)
`

const (
	listPrivateKeysStmt  = "SELECT &PrivateKey.* FROM %s"
	getPrivateKeyStmt    = "SELECT &PrivateKey.* FROM %s WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"
	createPrivateKeyStmt = "INSERT INTO %s (private_key) VALUES ($PrivateKey.private_key)"
	deletePrivateKeyStmt = "DELETE FROM %s WHERE private_key_id==$PrivateKey.private_key_id or private_key==$PrivateKey.private_key"
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(listPrivateKeysStmt, db.privateKeysTable), PrivateKey{})
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

// GetCertificateByID gets a certificate row from the repository from a given ID.
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

	stmt, err := sqlair.Prepare(fmt.Sprintf(getPrivateKeyStmt, db.privateKeysTable), PrivateKey{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Get(&pkRow)
	if err != nil {
		return nil, err
	}
	return &pkRow, nil
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreatePrivateKey(pk string) error {
	if err := ValidatePrivateKey(pk); err != nil {
		return errors.New("pk validation failed: " + err.Error())
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(createPrivateKeyStmt, db.privateKeysTable), PrivateKey{})
	if err != nil {
		return err
	}
	row := PrivateKey{
		PrivateKeyPEM: pk,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
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

	stmt, err := sqlair.Prepare(fmt.Sprintf(deletePrivateKeyStmt, db.privateKeysTable), PrivateKey{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, pkRow).Run()
	if err != nil {
		return err
	}
	return nil
}
