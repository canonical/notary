package db

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/encryption"
)

type JWTSecret struct {
	ID              int64  `db:"id"`
	EncryptedSecret string `db:"encrypted_secret"`
}

// createJWTSecret encrypts and stores the JWT secret in the database, there can only be one JWT secret.
func (db *Database) createJWTSecret(secret []byte) error {
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

// getJWTSecret retrieves and decrypts the only JWT secret from the database.
func (db *Database) getJWTSecret() ([]byte, error) {
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

// This secret should be generated once and stored in the database, encrypted.
func generateJWTSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return bytes, nil
}

// setUpJWTSecret checks if a JWT secret exists in the database, if not, it generates a new one and stores it.
func setUpJWTSecret(database *Database) ([]byte, error) {
	jwtSecret, err := database.getJWTSecret()
	if err != nil {
		// Generate new JWT secret if none exists
		if errors.Is(err, ErrNotFound) {
			jwtSecret, err = generateJWTSecret()
			if err != nil {
				return nil, err
			}
			if err := database.createJWTSecret(jwtSecret); err != nil {
				return nil, fmt.Errorf("failed to store JWT secret: %w", err)
			}
			return jwtSecret, nil
		} else {
			return nil, fmt.Errorf("failed to get JWT secret: %w", err)
		}
	}
	return jwtSecret, nil
}
