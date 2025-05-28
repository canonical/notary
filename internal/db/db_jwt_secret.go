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

// StoreJWTSecret encrypts and stores the JWT secret in the database
func (db *Database) StoreJWTSecret(secret []byte) error {
	// Encrypt the secret
	encryptedSecret, err := Encrypt(string(secret), db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt JWT secret: %w", err)
	}

	// Store in database
	jwtSecret := JWTSecret{
		ID:              1,
		EncryptedSecret: encryptedSecret,
	}

	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), db.stmts.StoreJWTSecret, jwtSecret).Get(&outcome)
	if err != nil {
		return fmt.Errorf("failed to store JWT secret: %w", err)
	}

	return nil
}

// GetJWTSecret retrieves and decrypts the JWT secret from the database
func (db *Database) GetJWTSecret() ([]byte, error) {
	// Get encrypted secret from database
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
