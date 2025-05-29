package db

import "fmt"

// ListPrivateKeys gets every PrivateKey entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	privateKeys, err := ListEntities[PrivateKey](db, db.stmts.ListPrivateKeys)
	if err != nil {
		return nil, err
	}
	for i := range privateKeys {
		decryptedPK, err := Decrypt(privateKeys[i].PrivateKeyPEM, db.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decrypt private key", err)
		}
		privateKeys[i].PrivateKeyPEM = decryptedPK
	}
	return privateKeys, nil
}

// GetPrivateKey gets a private key row from the repository from a given ID or PEM.
func (db *Database) GetPrivateKey(filter PrivateKeyFilter) (*PrivateKey, error) {
	pkRow := filter.AsPrivateKey()
	pk, err := GetOneEntity[PrivateKey](db, db.stmts.GetPrivateKey, *pkRow)
	if err != nil {
		return nil, err
	}
	decryptedPK, err := Decrypt(pk.PrivateKeyPEM, db.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt private key", ErrInternal)
	}
	pk.PrivateKeyPEM = decryptedPK
	return pk, nil
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		return 0, err
	}
	encryptedPK, err := Encrypt(pk, db.EncryptionKey)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to encrypt private key", ErrInternal)
	}
	row := PrivateKey{
		PrivateKeyPEM: encryptedPK,
	}

	return CreateEntity(db, db.stmts.CreatePrivateKey, row)
}

// DeletePrivateKey deletes a private key from the database.
func (db *Database) DeletePrivateKey(filter PrivateKeyFilter) error {
	pkRow := filter.AsPrivateKey()
	return DeleteEntity(db, db.stmts.DeletePrivateKey, pkRow)
}
