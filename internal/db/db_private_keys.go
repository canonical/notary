package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

// ListPrivateKeys gets every PrivateKey entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	privateKeys, err := ListEntities[PrivateKey](db, db.stmts.ListPrivateKeys)
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

	pk, err := GetOneEntity[PrivateKey](db, db.stmts.GetPrivateKey, pkRow)
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
	row := PrivateKey{
		PrivateKeyPEM: pk,
	}
	var outcome sqlair.Outcome
	err := db.conn.Query(context.Background(), db.stmts.CreatePrivateKey, row).Get(&outcome)
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
