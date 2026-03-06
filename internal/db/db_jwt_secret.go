package db

import (
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

type JWTSecret struct {
	ID              int64  `db:"id"`
	EncryptedSecret string `db:"encrypted_secret"`
}

// createJWTSecret encrypts and stores the JWT secret in the database, there can only be one JWT secret.
func (db *DatabaseRepository) CreateJWTSecret(secret []byte) error {
	encryptedSecret, err := utils.Encrypt(string(secret), db.EncryptionKey)
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
func (db *DatabaseRepository) GetJWTSecret() ([]byte, error) {
	jwtRow := JWTSecret{
		ID: 1,
	}
	secret, err := GetOneEntity[JWTSecret](db, db.stmts.GetJWTSecret, jwtRow)
	if err != nil {
		return nil, err
	}
	decryptedSecret, err := utils.Decrypt(secret.EncryptedSecret, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWT secret: %w", err)
	}

	return []byte(decryptedSecret), nil
}
