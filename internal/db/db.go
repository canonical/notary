// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Database is the object used to communicate with the established repository.
type Database struct {
	certificateTable string
	usersTable       string
	conn             *sqlair.DB
}

type CertificateRequest struct {
	ID int `db:"id"`

	CSR              string `db:"csr"`
	CertificateChain string `db:"certificate_chain"`
	RequestStatus    string `db:"request_status"`
}

type User struct {
	ID int `db:"id"`

	Username       string `db:"username"`
	HashedPassword string `db:"hashed_password"`
	Permissions    int    `db:"permissions"`
}

const (
	certificateRequestsTableName = "certificate_requests"
	usersTableName               = "users"
)

const queryCreateCSRsTable = `
	CREATE TABLE IF NOT EXISTS %s (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,

		csr TEXT NOT NULL UNIQUE, 
		certificate_chain TEXT DEFAULT '',
		request_status TEXT DEFAULT 'Outstanding', 
		
		CHECK (request_status IN ('Outstanding', 'Rejected', 'Revoked', 'Active')),
		CHECK (NOT (certificate_chain == '' AND request_status == 'Active' )),
		CHECK (NOT (certificate_chain != '' AND request_status == 'Outstanding'))
        CHECK (NOT (certificate_chain != '' AND request_status == 'Rejected'))
        CHECK (NOT (certificate_chain != '' AND request_status == 'Revoked'))
)`

const queryCreateUsersTable = `
	CREATE TABLE IF NOT EXISTS %s (
 		id INTEGER PRIMARY KEY AUTOINCREMENT,

		username TEXT NOT NULL UNIQUE,
		hashed_password TEXT NOT NULL,
		permissions INTEGER
)`

const (
	getAllCSRsStmt = "SELECT &CertificateRequest.* FROM %s"
	getCSRsStmt    = "SELECT &CertificateRequest.* FROM %s WHERE id==$CertificateRequest.id or csr==$CertificateRequest.csr"
	createCSRStmt  = "INSERT INTO %s (csr) VALUES ($CertificateRequest.csr)"
	updateCSRStmt  = "UPDATE %s SET certificate_chain=$CertificateRequest.certificate_chain, request_status=$CertificateRequest.request_status WHERE id==$CertificateRequest.id or csr==$CertificateRequest.csr"
	deleteCSRStmt  = "DELETE FROM %s WHERE id=$CertificateRequest.id or csr=$CertificateRequest.csr"
)

const (
	getAllUsersStmt = "SELECT &User.* from %s"
	getUserStmt     = "SELECT &User.* from %s WHERE id==$User.id or username==$User.username"
	createUserStmt  = "INSERT INTO %s (username, hashed_password, permissions) VALUES ($User.username, $User.hashed_password, $User.permissions)"
	updateUserStmt  = "UPDATE %s SET hashed_password=$User.hashed_password WHERE id==$User.id or username==$User.username"
	deleteUserStmt  = "DELETE FROM %s WHERE id==$User.id"
	getNumUsersStmt = "SELECT COUNT(*) AS &NumUsers.count FROM %s"
)

// RetrieveAllCSRs gets every CertificateRequest entry in the table.
func (db *Database) RetrieveAllCSRs() ([]CertificateRequest, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(getAllCSRsStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return nil, err
	}
	var csrs []CertificateRequest
	err = db.conn.Query(context.Background(), stmt).GetAll(&csrs)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return csrs, nil
		}
		return nil, err
	}
	return csrs, nil
}

// RetrieveCSRbyID gets a CSR row from the repository from a given ID.
func (db *Database) RetrieveCSRbyID(id int) (*CertificateRequest, error) {
	csr := CertificateRequest{
		ID: id,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCSRsStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, csr).Get(&csr)
	if err != nil {
		return nil, err
	}
	return &csr, nil
}

// RetrieveCSRbyCSR gets a given CSR row from the repository using the CSR text.
func (db *Database) RetrieveCSRbyCSR(csr string) (*CertificateRequest, error) {
	row := CertificateRequest{
		CSR: csr,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCSRsStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&row)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// CreateCSR creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCSR(csr string) error {
	if err := ValidateCertificateRequest(csr); err != nil {
		return errors.New("csr validation failed: " + err.Error())
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(createCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := CertificateRequest{
		CSR: csr,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// AddCertificateChainToCSRbyCSR adds a new certificate chain to a row for a given CSR string.
func (db *Database) AddCertificateChainToCSRbyCSR(csr string, cert string) error {
	err := ValidateCertificate(cert)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	err = CertificateMatchesCSR(cert, csr)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	certBundle := sanitizeCertificateBundle(cert)
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR:              csr,
		CertificateChain: certBundle,
		RequestStatus:    "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// AddCertificateChainToCSRbyID adds a new certificate chain to a row for a given row ID.
func (db *Database) AddCertificateToCSRbyID(id int, cert string) error {
	csr, err := db.RetrieveCSRbyID(id)
	if err != nil {
		return err
	}
	err = ValidateCertificate(cert)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	err = CertificateMatchesCSR(cert, csr.CSR)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	certBundle := sanitizeCertificateBundle(cert)
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		ID:               id,
		CertificateChain: certBundle,
		RequestStatus:    "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// RejectCSRbyCSR updates input CSR's row by setting the certificate bundle to "" and moving the row status to "Rejected".
func (db *Database) RejectCSRbyCSR(csr string) error {
	oldRow, err := db.RetrieveCSRbyCSR(csr)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		ID:               oldRow.ID,
		CSR:              oldRow.CSR,
		CertificateChain: "",
		RequestStatus:    "Rejected",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// RejectCSRbyCSR updates input ID's row by setting the certificate bundle to "" and sets the row status to "Rejected".
func (db *Database) RejectCSRbyID(id int) error {
	oldRow, err := db.RetrieveCSRbyID(id)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		ID:               oldRow.ID,
		CSR:              oldRow.CSR,
		CertificateChain: "",
		RequestStatus:    "Rejected",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// RevokeCSR updates the input CSR's row by setting the certificate bundle to "" and sets the row status to "Revoked".
func (db *Database) RevokeCSR(csr string) error {
	oldRow, err := db.RetrieveCSRbyCSR(csr)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		ID:               oldRow.ID,
		CSR:              oldRow.CSR,
		CertificateChain: "",
		RequestStatus:    "Revoked",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// DeleteCSRbyCSR removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCSRbyCSR(csr string) error {
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := CertificateRequest{
		CSR: csr,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// DeleteCSRByID removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCSRbyID(id int) error {
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteCSRStmt, db.certificateTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := CertificateRequest{
		ID: id,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// RetrieveAllUsers returns all of the users and their fields available in the database.
func (db *Database) RetrieveAllUsers() ([]User, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(getAllUsersStmt, db.usersTable), User{})
	if err != nil {
		return nil, err
	}
	var users []User
	err = db.conn.Query(context.Background(), stmt).GetAll(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

// RetrieveUser retrieves the name, password and the permission level of a user.
func (db *Database) RetrieveUserByID(id int) (*User, error) {
	row := User{
		ID: id,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getUserStmt, db.usersTable), User{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&row)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// RetrieveUser retrieves the id, password and the permission level of a user.
func (db *Database) RetrieveUserByUsername(name string) (*User, error) {
	row := User{
		Username: name,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getUserStmt, db.usersTable), User{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&row)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) error {
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(createUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		Username:       username,
		HashedPassword: string(pw),
		Permissions:    permission,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// UpdateUser updates the password of the given user.
// Just like with CreateUser, this function handles hashing and salting the password before storage.
func (db *Database) UpdateUserPassword(id int, password string) error {
	_, err := db.RetrieveUserByID(id)
	if err != nil {
		return err
	}
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		ID:             id,
		HashedPassword: string(pw),
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// DeleteUserByID removes a user from the table.
func (db *Database) DeleteUserByID(id int) error {
	_, err := db.RetrieveUserByID(id)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		ID: id,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

type NumUsers struct {
	Count int `db:"count"`
}

// NumUsers returns the number of users in the database.
func (db *Database) NumUsers() (int, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(getNumUsersStmt, db.usersTable), NumUsers{})
	if err != nil {
		return 0, err
	}
	result := NumUsers{}
	err = db.conn.Query(context.Background(), stmt).Get(&result)
	if err != nil {
		return 0, err
	}
	return result.Count, nil
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
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateCSRsTable, certificateRequestsTableName)); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(fmt.Sprintf(queryCreateUsersTable, usersTableName)); err != nil {
		return nil, err
	}
	db := new(Database)
	db.conn = sqlair.NewDB(sqlConnection)
	db.certificateTable = certificateRequestsTableName
	db.usersTable = usersTableName
	return db, nil
}
