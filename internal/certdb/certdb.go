// Package certdb provides a simplistic ORM to communicate with an SQL database for storage
package certdb

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
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

const queryCreateUsersTable = `CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	salt TEXT NOT NULL,
	permissions INTEGER,
)`
const (
	queryGetAllUsers = "SELECT * FROM users"
	queryGetUser     = "SELECT * FROM users WHERE user_id=?"
	queryCreateUser  = "INSERT INTO users (username, password, salt, permissions) VALUES (?, ?, ?, ?)"
	queryUpdateUser  = "UPDATE users SET password=?, salt=? WHERE user_id=?"
	queryDeleteUser  = "DELETE FROM users WHERE user_id=?"
)

// CertificateRequestRepository is the object used to communicate with the established repository.
type CertificateRequestsRepository struct {
	certificateTable string
	conn             *sql.DB
}

// A CertificateRequest struct represents an entry in the database.
// The object contains a Certificate Request, its matching Certificate if any, and the row ID.
type CertificateRequest struct {
	ID          int
	CSR         string
	Certificate string
}
type User struct {
	ID          int
	Username    string
	Password    string
	Salt        string
	Permissions int
}

// RetrieveAllCSRs gets every CertificateRequest entry in the table.
func (db *CertificateRequestsRepository) RetrieveAllCSRs() ([]CertificateRequest, error) {
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
func (db *CertificateRequestsRepository) RetrieveCSR(id string) (CertificateRequest, error) {
	var newCSR CertificateRequest
	row := db.conn.QueryRow(fmt.Sprintf(queryGetCSR, db.certificateTable), id)
	if err := row.Scan(&newCSR.ID, &newCSR.CSR, &newCSR.Certificate); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newCSR, errors.New("csr id not found")
		}
		return newCSR, err
	}
	return newCSR, nil
}

// CreateCSR creates a new entry in the repository.
// The given CSR must be valid and unique
func (db *CertificateRequestsRepository) CreateCSR(csr string) (int64, error) {
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
func (db *CertificateRequestsRepository) UpdateCSR(id string, cert string) (int64, error) {
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
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryUpdateCSR, db.certificateTable), cert, csr.ID)
	if err != nil {
		return 0, err
	}
	insertId, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return insertId, nil
}

// DeleteCSR removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *CertificateRequestsRepository) DeleteCSR(id string) (int64, error) {
	result, err := db.conn.Exec(fmt.Sprintf(queryDeleteCSR, db.certificateTable), id)
	if err != nil {
		return 0, err
	}
	deleteId, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleteId == 0 {
		return 0, errors.New("csr id not found")
	}
	return deleteId, nil
}

func (db *CertificateRequestsRepository) RetrieveAllUsers() ([]User, error) {
	rows, err := db.conn.Query(queryGetAllUsers)
	if err != nil {
		return nil, err
	}

	var allUsers []User
	defer rows.Close()
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Salt, &user.Permissions); err != nil {
			return nil, err
		}
		allUsers = append(allUsers, user)
	}
	return allUsers, nil
}
func (db *CertificateRequestsRepository) RetrieveUser(id string) (User, error) {
	var newUser User
	row := db.conn.QueryRow(queryGetUser, id)
	if err := row.Scan(&newUser.ID, &newUser.Username, &newUser.Password, &newUser.Salt, &newUser.Permissions); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newUser, errors.New("user id not found")
		}
		return newUser, err
	}
	return newUser, nil
}

// func (db *CertificateRequestsRepository) CreateUser(username, password, permissions string) (int64, error) {
// 	passwordHash, salt, err := something bcrypt
// 	result, err := db.conn.Exec(queryCreateUser, username, passwordHash, salt, permissions)
// 	if err != nil {
// 		return 0, err
// 	}
// 	id, err := result.LastInsertId()
// 	if err != nil {
// 		return 0, err
// 	}
// 	return id, nil
// }

func (db *CertificateRequestsRepository) UpdateUser(id, password string) (int64, error) {
	user, err := db.RetrieveUser(id)
	if err != nil {
		return 0, err
	}
	// passwordHash, salt := something bcrypt
	result, err := db.conn.Exec(queryUpdateUser, user.ID)
	if err != nil {
		return 0, err
	}
	insertId, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return insertId, nil
}

func (db *CertificateRequestsRepository) DeleteUser(id string) (int64, error) {
	result, err := db.conn.Exec(queryDeleteCSR, id)
	if err != nil {
		return 0, err
	}
	deleteId, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleteId == 0 {
		return 0, errors.New("user id not found")
	}
	return deleteId, nil
}

// Close closes the connection to the repository cleanly.
func (db *CertificateRequestsRepository) Close() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.Close(); err != nil {
		return err
	}
	return nil
}

// NewCertificateRequestsRepository connects to a given table in a given database,
// stores the connection information and returns an object containing the information.
// The database path must be a valid file path or ":memory:".
// The table will be created if it doesn't exist in the format expected by the package.
func NewCertificateRequestsRepository(databasePath string, tableName string) (*CertificateRequestsRepository, error) {
	conn, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(fmt.Sprintf(queryCreateCSRsTable, tableName)); err != nil {
		return nil, err
	}
	db := new(CertificateRequestsRepository)
	db.conn = conn
	db.certificateTable = tableName
	return db, nil
}
