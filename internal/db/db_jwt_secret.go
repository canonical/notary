package db

import (
	"fmt"

	"github.com/canonical/notary/internal/encryption"
)

// CreateJWTSecret encrypts and stores the JWT secret in the database, there can only be one JWT secret.
func (db *Database) CreateJWTSecret(secret []byte) error {
	encryptedSecret, err := encryption.Encrypt(string(secret), db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt JWT secret: %w", ErrInternal)
	}
	jwtSecret := JWTSecret{
		ID:              1,
		EncryptedSecret: encryptedSecret,
	}
	_, err = CreateEntity[JWTSecret](db, db.stmts.CreateJWTSecret, jwtSecret)
	return err
}

// GetJWTSecret retrieves and decrypts the only JWT secret from the database.
func (db *Database) GetJWTSecret() ([]byte, error) {
	jwtRow := JWTSecret{
		ID: 1,
	}
	secret, err := GetOneEntity[JWTSecret](db, db.stmts.GetJWTSecret, jwtRow)
	if err != nil {
		return nil, err
	}
	decryptedSecret, err := encryption.Decrypt(secret.EncryptedSecret, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWT secret: %w", err)
	}

	return []byte(decryptedSecret), nil
}

// DeleteJWTSecret deletes the JWT secret from the database
func (db *Database) DeleteJWTSecret() error {
	return DeleteEntity[JWTSecret](db, db.stmts.DeleteJWTSecret, JWTSecret{ID: 1})
}
