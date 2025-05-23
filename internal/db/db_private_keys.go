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
	pkRow, err := filter.AsPrivateKey()
	if err != nil {
		return nil, err
	}

	pk, err := GetOneEntity(db, db.stmts.GetPrivateKey, *pkRow)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// CreatePrivateKey creates a new private key entry in the repository. The string must be a valid private key and unique.
func (db *Database) CreatePrivateKey(pk string) (int64, error) {
	if err := ValidatePrivateKey(pk); err != nil {
		return 0, err
	}

	row := PrivateKey{
		PrivateKeyPEM: pk,
	}

	insertedRowID, err := CreateEntity(db, db.stmts.CreatePrivateKey, row)
	if err != nil {
		return 0, err
	}
	return insertedRowID, nil
}

// DeletePrivateKey deletes a private key from the database.
func (db *Database) DeletePrivateKey(filter PrivateKeyFilter) error {
	pkRow, err := db.GetPrivateKey(filter)
	if err != nil {
		return err
	}

	err = DeleteEntity(db, db.stmts.DeletePrivateKey, pkRow)
	if err != nil {
		return err
	}
	return nil
}
