package db

import (
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

// GetOrCreateACMEAccount returns the existing ACME account for (email, directoryURL),
// or creates a new one if none exists. The returned account has a plaintext private key.
func (db *DatabaseRepository) GetOrCreateACMEAccount(email, directoryURL, privKeyPEM, regURI, regBody string) (*ACMEAccount, error) {
	encryptedPK, err := utils.Encrypt(privKeyPEM, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encrypt ACME account private key", ErrInternal)
	}
	row := ACMEAccount{
		Email:            email,
		DirectoryURL:     directoryURL,
		PrivateKeyPEM:    encryptedPK,
		RegistrationURI:  regURI,
		RegistrationBody: regBody,
	}
	id, err := CreateEntity[ACMEAccount](db, db.stmts.InsertACMEAccount, row)
	if err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return db.GetACMEAccountByEmailAndURL(email, directoryURL)
		}
		return nil, err
	}
	return &ACMEAccount{
		ID:               id,
		Email:            email,
		DirectoryURL:     directoryURL,
		PrivateKeyPEM:    privKeyPEM,
		RegistrationURI:  regURI,
		RegistrationBody: regBody,
	}, nil
}

// GetDecryptedACMEAccount retrieves an ACME account by ID and decrypts its private key.
func (db *DatabaseRepository) GetDecryptedACMEAccount(id int64) (*ACMEAccount, error) {
	row := ACMEAccount{ID: id}
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

// UpdateACMEAccount encrypts the private key and updates the account row.
func (db *DatabaseRepository) UpdateACMEAccount(id int64, privKeyPEM, regURI, regBody string) error {
	encryptedPK, err := utils.Encrypt(privKeyPEM, db.EncryptionKey)
	if err != nil {
		return fmt.Errorf("%w: failed to encrypt ACME account private key", ErrInternal)
	}
	row := ACMEAccount{
		ID:               id,
		PrivateKeyPEM:    encryptedPK,
		RegistrationURI:  regURI,
		RegistrationBody: regBody,
	}
	return UpdateEntity[ACMEAccount](db, db.stmts.UpdateACMEAccount, row)
}

// LinkAccountToServer sets acme_account_id on the given server row.
func (db *DatabaseRepository) LinkAccountToServer(serverID, accountID int64) error {
	row := ACMEServer{
		ID:            serverID,
		ACMEAccountID: &accountID,
	}
	return UpdateEntity[ACMEServer](db, db.stmts.LinkACMEAccountToServer, row)
}

// GetACMEAccountByEmailAndURL fetches an account by (email, directoryURL) and decrypts its private key.
// Returns ErrNotFound if no matching account exists.
func (db *DatabaseRepository) GetACMEAccountByEmailAndURL(email, directoryURL string) (*ACMEAccount, error) {
	row := ACMEAccount{Email: email, DirectoryURL: directoryURL}
	account, err := GetOneEntity[ACMEAccount](db, db.stmts.GetACMEAccountByEmailAndURL, row)
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
