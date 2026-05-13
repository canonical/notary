package db

import (
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

// CreateACMEAccount encrypts the private key and persists the ACME account as the singleton row.
func (db *DatabaseRepository) CreateACMEAccount(email, privKeyPEM, regURI, regBody string) error {
	encryptedPK, err := utils.Encrypt(privKeyPEM, db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("%w: failed to encrypt ACME account private key", ErrInternal)
	}
	row := ACMEAccount{
		ID:               1,
		Email:            email,
		PrivateKeyPEM:    encryptedPK,
		RegistrationURI:  regURI,
		RegistrationBody: regBody,
	}
	_, err = CreateEntity[ACMEAccount](db, db.stmts.CreateACMEAccount, row)
	return err
}

// GetDecryptedACMEAccount retrieves the ACME account and decrypts its private key.
func (db *DatabaseRepository) GetDecryptedACMEAccount() (*ACMEAccount, error) {
	row := ACMEAccount{ID: 1}
	account, err := GetOneEntity[ACMEAccount](db, db.stmts.GetACMEAccount, row)
	if err != nil {
		return nil, err
	}
	decryptedPK, err := utils.Decrypt(account.PrivateKeyPEM, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt ACME account private key", ErrInternal)
	}
	account.PrivateKeyPEM = decryptedPK
	return account, nil
}

// ACMEAccountExists returns true if an ACME account row exists in the database.
func (db *DatabaseRepository) ACMEAccountExists() (bool, error) {
	_, err := db.GetDecryptedACMEAccount()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
