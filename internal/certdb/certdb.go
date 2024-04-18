// Package certdb provides a simplistic ORM to communicate with an SQL database for storage
package certdb

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

const queryCreateTable = "CREATE TABLE IF NOT EXISTS %s (CSR VARCHAR PRIMARY KEY UNIQUE NOT NULL, Certificate VARCHAR DEFAULT '')"

const queryGetAllCSRs = "SELECT rowid, * FROM %s"
const queryGetCSR = "SELECT rowid, * FROM %s WHERE rowid=?"
const queryCreateCSR = "INSERT INTO %s (CSR) VALUES (?)"
const queryUpdateCSR = "UPDATE %s SET Certificate=? WHERE rowid=?"
const queryDeleteCSR = "DELETE FROM %s WHERE rowid=?"

// CertificateRequestRepository is the object used to communicate with the established repository.
type CertificateRequestsRepository struct {
	table string
	conn  *sql.DB
}

// A CertificateRequest struct represents an entry in the database.
// The object contains a Certificate Request, its matching Certificate if any, and the row ID.
type CertificateRequest struct {
	ID          int
	CSR         string
	Certificate string
}

// RetrieveAll gets every CertificateRequest entry in the table.
func (db *CertificateRequestsRepository) RetrieveAll() ([]CertificateRequest, error) {
	rows, err := db.conn.Query(fmt.Sprintf(queryGetAllCSRs, db.table))
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

// Retrieve gets a given CSR from the repository.
// It returns the row id and matching certificate alongside the CSR in a CertificateRequest object.
func (db *CertificateRequestsRepository) Retrieve(id string) (CertificateRequest, error) {
	var newCSR CertificateRequest
	row := db.conn.QueryRow(fmt.Sprintf(queryGetCSR, db.table), id)
	if err := row.Scan(&newCSR.ID, &newCSR.CSR, &newCSR.Certificate); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return newCSR, errors.New("csr id not found")
		}
		return newCSR, err
	}
	return newCSR, nil
}

// Create creates a new entry in the repository.
// The given CSR must be valid and unique
func (db *CertificateRequestsRepository) Create(csr string) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, err
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryCreateCSR, db.table), csr)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Update adds a new cert to the given CSR in the repository.
// The given certificate must share the public key of the CSR and must be valid.
func (db *CertificateRequestsRepository) Update(id string, cert string) (int64, error) {
	if err := ValidateCertificate(cert); err != nil {
		return 0, err
	}
	csr, err := db.Retrieve(id)
	if err != nil {
		return 0, err
	}
	if err := CertificateMatchesCSR(cert, csr.CSR); err != nil {
		return 0, err
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryUpdateCSR, db.table), cert, csr.ID)
	if err != nil {
		return 0, err
	}
	insertId, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return insertId, nil
}

// Delete removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *CertificateRequestsRepository) Delete(id string) (int64, error) {
	result, err := db.conn.Exec(fmt.Sprintf(queryDeleteCSR, db.table), id)
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
	if _, err := conn.Exec(fmt.Sprintf(queryCreateTable, tableName)); err != nil {
		return nil, err
	}
	db := new(CertificateRequestsRepository)
	db.conn = conn
	db.table = tableName
	return db, nil
}
