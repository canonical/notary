package certdb

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const queryCreateTable = `CREATE TABLE IF NOT EXISTS CertificateRequests (
	id INT PRIMARY KEY UNIQUE,
	CSR VARCHAR UNIQUE NOT NULL,
	Certificate VARCHAR DEFAULT ""
	)`

type CertificateRequests struct {
	conn *sql.DB
	data []CertificateRequest
}

type CertificateRequest struct {
	ID          int
	CSR         string
	Certificate string
}

func (c *CertificateRequests) Create() error {
	return nil
}

func (c *CertificateRequests) Retrieve() (*CertificateRequest, error) {
	return nil, sql.ErrNoRows
}

func (c *CertificateRequests) Update() error {

	return nil
}

func (c *CertificateRequests) Delete() error {

	return nil
}

func (t *CertificateRequests) Connect() error {
	// Connect to local DB
	conn, err := sql.Open("sqlite3", "./certs.db")
	if err != nil {
		return err
	}
	t.conn = conn
	if err := t.conn.Ping(); err != nil {
		return err
	}
	if _, err := t.conn.Exec(queryCreateTable); err != nil {
		return err
	}
	rows, err := t.conn.Query("SELECT * FROM CertificateRequests")
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var csr CertificateRequest
		if err := rows.Scan(&csr.ID, &csr.CSR, &csr.Certificate); err != nil {
			return err
		}
		t.data = append(t.data, csr)
	}

	return nil
}

func (t *CertificateRequests) Disconnect() {
	// Disconnect from database and table
}
