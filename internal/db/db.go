// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"database/sql"

	"github.com/canonical/sqlair"
	_ "github.com/mattn/go-sqlite3"
)

// Database is the object used to communicate with the established repository.
type Database struct {
	conn *sqlair.DB
}

// Close closes the connection to the repository cleanly.
func (db *Database) Close() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.PlainDB().Close(); err != nil {
		return err
	}
	return nil
}

// NewDatabase connects to a given table in a given database,
// stores the connection information and returns an object containing the information.
// The database path must be a valid file path or ":memory:".
// The table will be created if it doesn't exist in the format expected by the package.
func NewDatabase(databasePath string) (*Database, error) {
	sqlConnection, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(queryCreateCertificateRequestsTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(queryCreateCertificatesTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(queryCreateUsersTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(queryCreatePrivateKeysTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(queryCreateCertificateAuthoritiesTable); err != nil {
		return nil, err
	}
	db := new(Database)
	db.conn = sqlair.NewDB(sqlConnection)
	return db, nil
}
