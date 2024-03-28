package certdb

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

const queryCreateTable = "CREATE TABLE IF NOT EXISTS %s (CSR VARCHAR PRIMARY KEY UNIQUE NOT NULL, Certificate VARCHAR)"

const queryGetAllCSRs = "SELECT rowid, * FROM %s"
const queryGetCSR = "SELECT rowid, * FROM %s WHERE CSR=?"
const queryCreateCSR = "INSERT INTO %s (CSR) VALUES (?)"
const queryUpdateCSR = "UPDATE %s SET Certificate=? WHERE CSR=?"
const queryDeleteCSR = "DELETE FROM %s WHERE CSR=?"

type CertificateRequests struct {
	table string
	conn  *sql.DB
}

type CertificateRequest struct {
	ID          int
	CSR         string
	Certificate *string
}

func (db *CertificateRequests) RetrieveAll() ([]CertificateRequest, error) {
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

func (db *CertificateRequests) Retrieve(csr string) (*CertificateRequest, error) {
	var newCSR CertificateRequest
	row := db.conn.QueryRow(fmt.Sprintf(queryGetCSR, db.table), csr)
	if err := row.Scan(&newCSR.ID, &newCSR.CSR, &newCSR.Certificate); err != nil {
		return nil, err
	}
	return &newCSR, nil
}

func (db *CertificateRequests) Create(csr string) (int64, error) {
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

func (db *CertificateRequests) Update(csr string, cert string) (int64, error) {
	if err := ValidateCertificate(cert, csr); err != nil {
		return 0, err
	}
	result, err := db.conn.Exec(fmt.Sprintf(queryUpdateCSR, db.table), cert, csr)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *CertificateRequests) Delete(csr string) error {
	_, err := db.conn.Exec(fmt.Sprintf(queryDeleteCSR, db.table), csr)
	if err != nil {
		return err
	}
	return nil
}

func (db *CertificateRequests) Connect(databasePath string, tableName string) error {
	conn, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return err
	}
	db.table = tableName
	db.conn = conn
	if _, err := db.conn.Exec(fmt.Sprintf(queryCreateTable, db.table)); err != nil {
		return err
	}
	return nil
}

func (db *CertificateRequests) Disconnect() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.Close(); err != nil {
		return err
	}
	return nil
}
