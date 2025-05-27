package db

// ListPrivateKeys gets every PrivateKey entry in the table.
func (db *Database) ListPrivateKeys() ([]PrivateKey, error) {
	privateKeys, err := ListEntities[PrivateKey](db, db.stmts.ListPrivateKeys)
	if err != nil {
		return nil, err
	}
	return privateKeys, nil
}

// GetPrivateKey gets a private key row from the repository from a given ID or PEM.
func (db *Database) GetPrivateKey(filter PrivateKeyFilter) (*PrivateKey, error) {
	pkRow := filter.AsPrivateKey()
	return GetOneEntity[PrivateKey](db, db.stmts.GetPrivateKey, *pkRow)
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		return 0, err
	}

	row := PrivateKey{
		PrivateKeyPEM: pk,
	}

	return CreateEntity(db, db.stmts.CreatePrivateKey, row)
}

// DeletePrivateKey deletes a private key from the database.
func (db *Database) DeletePrivateKey(filter PrivateKeyFilter) error {
	pkRow := filter.AsPrivateKey()
	return DeleteEntity(db, db.stmts.DeletePrivateKey, pkRow)
}
