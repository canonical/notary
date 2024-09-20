// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	certificateRequestsTableName = "CertificateRequests"
	usersTableName               = "users"
)

const queryCreateCSRsTable = `CREATE TABLE IF NOT EXISTS %s (
	csr TEXT PRIMARY KEY UNIQUE NOT NULL, 
	certificate TEXT DEFAULT ''
)`

const (
	queryGetAllCSRs = "SELECT rowid, * FROM %s"
	queryGetCSR     = "SELECT rowid, * FROM %s WHERE rowid=?"
	queryCreateCSR  = "INSERT INTO %s (csr) VALUES (?)"
	queryUpdateCSR  = "UPDATE %s SET certificate=? WHERE rowid=?"
	queryDeleteCSR  = "DELETE FROM %s WHERE rowid=?"
)

const queryCreateUsersTable = `CREATE TABLE IF NOT EXISTS %s (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	permissions INTEGER
)`

const (
	queryGetAllUsers       = "SELECT * FROM %s"
	queryGetUser           = "SELECT * FROM %s WHERE user_id=?"
	queryGetUserByUsername = "SELECT * FROM %s WHERE username=?"
	queryCreateUser        = "INSERT INTO %s (username, password, permissions) VALUES (?, ?, ?)"
	queryUpdateUser        = "UPDATE %s SET password=? WHERE user_id=?"
	queryDeleteUser        = "DELETE FROM %s WHERE user_id=?"
	queryGetNumUsers       = "SELECT COUNT(*) FROM %s"
)

// CertificateRequestRepository is the object used to communicate with the established repository.
type Database struct {
	certificateTable string
	usersTable       string
	conn             *sql.DB
}

// A CertificateRequest struct represents an entry in the database.
// The object contains a Certificate Request, its matching Certificate if any, and the row ID.
type CertificateRequest struct {
	ID          int    `json:"id"`
	CSR         string `json:"csr"`
	Certificate string `json:"certificate"`
}
type User struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	Permissions int    `json:"permissions"`
}

var ErrIdNotFound = errors.New("id not found")

// RetrieveAllCSRs gets every CertificateRequest entry in the table.
func (db *Database) RetrieveAllCSRs() ([]CertificateRequest, error) {
	rows, err := db.conn.Query(fmt.Sprintf(queryGetAllCSRs, db.certificateTable))
	if err != nil {
		return nil, err
	}

	var allCsrs []CertificateRequest
	defer rows.Close()
	for rows.Next() {
		var csr CertificateRequest
		if err := rows.Scan(&csr.ID, &csr.CSR, &csr.Certificate); err != nil {
			return nil, err
		}
		allCsrs = append(allCsrs, csr)
	}
	return allCsrs, nil
}

// RetrieveCSR gets a given CSR from the repository.
// It returns the row id and matching certificate alongside the CSR in a CertificateRequest object.
func (db *Database) RetrieveCSR(id string) (CertificateRequest, error) {
	var newCSR CertificateRequest
	row := db.conn.QueryRow(fmt.Sprintf(queryGetCSR, db.certificateTable), id)
	if err := row.Scan(&newCSR.ID, &newCSR.CSR, &newCSR.Certificate); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newCSR, ErrIdNotFound
		}
		return newCSR, err
	}
	return newCSR, nil
}

// CreateCSR creates a new entry in the repository.
// The given CSR must be valid and unique
func (db *Database) CreateCSR(csr string) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, errors.New("csr validation failed: " + err.Error())
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryCreateCSR, db.certificateTable), csr)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// UpdateCSR adds a new cert to the given CSR in the repository.
// The given certificate must share the public key of the CSR and must be valid.
func (db *Database) UpdateCSR(id string, cert string) (int64, error) {
	csr, err := db.RetrieveCSR(id)
	if err != nil {
		return 0, err
	}
	if cert != "rejected" && cert != "" {
		err = ValidateCertificate(cert)
		if err != nil {
			return 0, errors.New("cert validation failed: " + err.Error())
		}
		err = CertificateMatchesCSR(cert, csr.CSR)
		if err != nil {
			return 0, errors.New("cert validation failed: " + err.Error())
		}
		cert = sanitizeCertificateBundle(cert)
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryUpdateCSR, db.certificateTable), cert, csr.ID)
	if err != nil {
		return 0, err
	}
	affectedRows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affectedRows, nil
}

// DeleteCSR removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCSR(id string) (int64, error) {
	result, err := db.conn.Exec(fmt.Sprintf(queryDeleteCSR, db.certificateTable), id)
	if err != nil {
		return 0, err
	}
	deleteId, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleteId == 0 {
		return 0, ErrIdNotFound
	}
	return deleteId, nil
}

// RetrieveAllUsers returns all of the users and their fields available in the database.
func (db *Database) RetrieveAllUsers() ([]User, error) {
	rows, err := db.conn.Query(fmt.Sprintf(queryGetAllUsers, db.usersTable))
	if err != nil {
		return nil, err
	}

	var allUsers []User
	defer rows.Close()
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Permissions); err != nil {
			return nil, err
		}
		allUsers = append(allUsers, user)
	}
	return allUsers, nil
}

// RetrieveUser retrieves the name, password and the permission level of a user.
func (db *Database) RetrieveUser(id string) (User, error) {
	var newUser User
	row := db.conn.QueryRow(fmt.Sprintf(queryGetUser, db.usersTable), id)
	if err := row.Scan(&newUser.ID, &newUser.Username, &newUser.Password, &newUser.Permissions); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newUser, ErrIdNotFound
		}
		return newUser, err
	}
	return newUser, nil
}

// RetrieveUser retrieves the id, password and the permission level of a user.
func (db *Database) RetrieveUserByUsername(name string) (User, error) {
	var newUser User
	row := db.conn.QueryRow(fmt.Sprintf(queryGetUserByUsername, db.usersTable), name)
	if err := row.Scan(&newUser.ID, &newUser.Username, &newUser.Password, &newUser.Permissions); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newUser, ErrIdNotFound
		}
		return newUser, err
	}
	return newUser, nil
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) (int64, error) {
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryCreateUser, db.usersTable), username, pw, permission)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// UpdateUser updates the password of the given user.
// Just like with CreateUser, this function handles hashing and salting the password before storage.
func (db *Database) UpdateUser(id, password string) (int64, error) {
	user, err := db.RetrieveUser(id)
	if err != nil {
		return 0, err
	}
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryUpdateUser, db.usersTable), pw, user.ID)
	if err != nil {
		return 0, err
	}
	affectedRows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affectedRows, nil
}

// DeleteUser removes a user from the table.
func (db *Database) DeleteUser(id string) (int64, error) {
	result, err := db.conn.Exec(fmt.Sprintf(queryDeleteUser, db.usersTable), id)
	if err != nil {
		return 0, err
	}
	deleteId, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleteId == 0 {
		return 0, ErrIdNotFound
	}
	return deleteId, nil
}

func (db *Database) NumUsers() (int, error) {
	var numUsers int
	row := db.conn.QueryRow(fmt.Sprintf(queryGetNumUsers, db.usersTable))
	if err := row.Scan(&numUsers); err != nil {
		return 0, err
	}
	return numUsers, nil
}

// Close closes the connection to the repository cleanly.
func (db *Database) Close() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.Close(); err != nil {
		return err
	}
	return nil
}

// NewDatabase connects to a given table in a given database,
// stores the connection information and returns an object containing the information.
// The database path must be a valid file path or ":memory:".
// The table will be created if it doesn't exist in the format expected by the package.
func NewDatabase(databasePath string) (*Database, error) {
	conn, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(fmt.Sprintf(queryCreateCSRsTable, certificateRequestsTableName)); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(fmt.Sprintf(queryCreateUsersTable, usersTableName)); err != nil {
		return nil, err
	}
	db := new(Database)
	db.conn = conn
	db.certificateTable = certificateRequestsTableName
	db.usersTable = usersTableName
	return db, nil
}
