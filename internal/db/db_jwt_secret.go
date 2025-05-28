package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type JWTSecret struct {
	ID              int64  `db:"id"`
	EncryptedSecret string `db:"encrypted_secret"`
}

// CreateJWTSecret encrypts and stores the JWT secret in the database, there can only be one JWT secret.
func (db *Database) CreateJWTSecret(secret []byte) error {
	currentSecret, err := db.GetJWTSecret()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: failed to check if JWT secret already exists", ErrInternal)
	}
	if currentSecret != nil {
		return fmt.Errorf("%w: JWT secret already exists", ErrAlreadyExists)
	}
	encryptedSecret, err := Encrypt(string(secret), db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("%w: failed to encrypt JWT secret", ErrInternal)
	}

	jwtSecret := JWTSecret{
		ID:              1,
		EncryptedSecret: encryptedSecret,
	}

	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), db.stmts.CreateJWTSecret, jwtSecret).Get(&outcome)
	if err != nil {
		return fmt.Errorf("%w: failed to create JWT secret", ErrInternal)
	}
	_, err = outcome.Result().LastInsertId()
	if err != nil {
		return fmt.Errorf("%w: failed to create JWT secret", ErrInternal)
	}
	return nil
}

// GetJWTSecret retrieves and decrypts the only JWT secret from the database.
func (db *Database) GetJWTSecret() ([]byte, error) {
	jwtRow := JWTSecret{
		ID: 1,
	}
	secret, err := GetOneEntity[JWTSecret](db, db.stmts.GetJWTSecret, jwtRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: no JWT secret found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query JWT secret: %w", err)
	}
	decryptedSecret, err := Decrypt(secret.EncryptedSecret, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWT secret: %w", err)
	}

	return []byte(decryptedSecret), nil
}

// DeleteJWTSecret deletes the JWT secret from the database
func (db *Database) DeleteJWTSecret() error {
	_, err := db.GetJWTSecret()
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), db.stmts.DeleteJWTSecret, JWTSecret{ID: 1}).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete JWT secret", ErrInternal)
	}
	return nil
}
