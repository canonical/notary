// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"database/sql"
	"fmt"

	"github.com/canonical/sqlair"
	_ "github.com/mattn/go-sqlite3"
)

// Database is the object used to communicate with the established repository.
type Database struct {
	certificateRequestsTable    string
	certificatesTable           string
	usersTable                  string
	privateKeysTable            string
	certificateAuthoritiesTable string
	conn                        *sqlair.DB
}

const (
	certificateRequestsTableName    = "certificate_requests"
	certificatesTableName           = "certificates"
	usersTableName                  = "users"
	privateKeysTableName            = "private_keys"
	certificateAuthoritiesTableName = "certificate_authorities"
)

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
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateCertificateRequestsTable, certificateRequestsTableName)); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateCertificatesTable, certificatesTableName)); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateUsersTable, usersTableName)); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreatePrivateKeysTable, privateKeysTableName)); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateCertificateAuthoritiesTable, certificateAuthoritiesTableName)); err != nil {
		return nil, err
	}
	db := new(Database)
	db.conn = sqlair.NewDB(sqlConnection)
	db.certificateRequestsTable = certificateRequestsTableName
	db.certificatesTable = certificatesTableName
	db.usersTable = usersTableName
	db.privateKeysTable = privateKeysTableName
	db.certificateAuthoritiesTable = certificateAuthoritiesTableName
	return db, nil
}
