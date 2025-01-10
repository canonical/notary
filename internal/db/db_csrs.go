package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type CertificateRequest struct {
	CSR_ID int `db:"csr_id"`

	CSR           string `db:"csr"`
	Status        string `db:"status"`
	CertificateID int    `db:"certificate_id"`
}

type CertificateRequestWithChain struct {
	CSR_ID int `db:"csr_id"`

	CSR              string `db:"csr"`
	Status           string `db:"status"`
	CertificateChain string `db:"certificate_chain"`
}

const queryCreateCertificateRequestsTable = `
	CREATE TABLE IF NOT EXISTS %s (
	    csr_id INTEGER PRIMARY KEY AUTOINCREMENT,

		csr TEXT NOT NULL UNIQUE, 
		certificate_id INTEGER,
		status TEXT DEFAULT 'Outstanding', 
		
		CHECK (status IN ('Outstanding', 'Rejected', 'Revoked', 'Active')),
		CHECK (NOT (certificate_id == NULL AND status == 'Active' )),
		CHECK (NOT (certificate_id != NULL AND status == 'Outstanding'))
        CHECK (NOT (certificate_id != NULL AND status == 'Rejected'))
        CHECK (NOT (certificate_id != NULL AND status == 'Revoked'))
)`

const (
	listCertificateRequestsStmt  = "SELECT &CertificateRequest.* FROM %s"
	getCertificateRequestStmt    = "SELECT &CertificateRequest.* FROM %s WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	updateCertificateRequestStmt = "UPDATE %s SET certificate_id=$CertificateRequest.certificate_id, status=$CertificateRequest.status WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	createCertificateRequestStmt = "INSERT INTO %s (csr) VALUES ($CertificateRequest.csr)"
	deleteCertificateRequestStmt = "DELETE FROM %s WHERE csr_id=$CertificateRequest.csr_id or csr=$CertificateRequest.csr"

	listCertificateRequestsWithCertificatesStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT 
        csr.csr_id,
        csr.csr,
		csr.status,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM %s csr
    LEFT JOIN %s cert 
      ON csr.certificate_id = cert.certificate_id
    
    UNION ALL
    
    -- Recursive Query: Find the issuer certificate in the certificates table
    SELECT 
        cc.csr_id,
        cc.csr,
		cc.status,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        cc.chain || CHAR(10) || cert.certificate AS chain
    FROM %s cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT 
	&CertificateRequestWithChain.csr_id,
	&CertificateRequestWithChain.csr,
	&CertificateRequestWithChain.status,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain
WHERE chain = '' OR issuer_id = 0`
	getCertificateRequestWithCertificateStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT 
        csr.csr_id,
        csr.csr,
		csr.status,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM %s csr
    LEFT JOIN %s cert 
      ON csr.certificate_id = cert.certificate_id
    
    UNION ALL
    
    -- Recursive Query: Find the issuer certificate in the certificates table
    SELECT 
        cc.csr_id,
        cc.csr,
		cc.status,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        cc.chain || CHAR(10) || cert.certificate AS chain
    FROM %s cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT 
	&CertificateRequestWithChain.csr_id,
	&CertificateRequestWithChain.csr,
	&CertificateRequestWithChain.status,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain
WHERE (csr_id = $CertificateRequestWithChain.csr_id OR csr = $CertificateRequestWithChain.csr) AND (chain = '' OR issuer_id = 0)`
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequests() ([]CertificateRequest, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(listCertificateRequestsStmt, db.certificateRequestsTable), CertificateRequest{})
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

// ListCertificateRequestWithCertificates gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificates() ([]CertificateRequestWithChain, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(listCertificateRequestsWithCertificatesStmt, db.certificateRequestsTable, db.certificatesTable, db.certificatesTable), CertificateRequestWithChain{})
	if err != nil {
		return nil, err
	}
	var csrs []CertificateRequestWithChain
	err = db.conn.Query(context.Background(), stmt).GetAll(&csrs)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return csrs, nil
		}
		return nil, err
	}
	return csrs, nil
}

// GetCertificateRequestByID gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequest(filter CSRFilter) (*CertificateRequest, error) {
	var csrRow CertificateRequest

	switch {
	case filter.ID != nil:
		csrRow = CertificateRequest{CSR_ID: *filter.ID}
	case filter.PEM != nil:
		csrRow = CertificateRequest{CSR: *filter.PEM}
	default:
		return nil, fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, csrRow).Get(&csrRow)
	if err != nil {
		return nil, err
	}
	return &csrRow, nil
}

// GetCertificateRequestAndChain gets a CSR row from the repository from a given ID.
func (db *Database) GetCertificateRequestAndChain(filter CSRFilter) (*CertificateRequestWithChain, error) {
	var csrRow CertificateRequestWithChain

	switch {
	case filter.ID != nil:
		csrRow = CertificateRequestWithChain{CSR_ID: *filter.ID}
	case filter.PEM != nil:
		csrRow = CertificateRequestWithChain{CSR: *filter.PEM}
	default:
		return nil, fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateRequestWithCertificateStmt, db.certificateRequestsTable, db.certificatesTable, db.certificatesTable), CertificateRequestWithChain{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, csrRow).Get(&csrRow)
	if err != nil {
		return nil, err
	}
	return &csrRow, nil
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCertificateRequest(csr string) error {
	if err := ValidateCertificateRequest(csr); err != nil {
		return errors.New("csr validation failed: " + err.Error())
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(createCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := CertificateRequest{
		CSR: csr,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// RejectCertificateRequest updates input CSR's row by setting the certificate bundle to "" and moving the row status to "Rejected".
func (db *Database) RejectCertificateRequest(filter CSRFilter) error {
	oldRow, err := db.GetCertificateRequest(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR_ID:        oldRow.CSR_ID,
		CSR:           oldRow.CSR,
		CertificateID: 0,
		Status:        "Rejected",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// RevokeCertificate updates the input CSR's row by setting the certificate bundle to "" and sets the row status to "Revoked".
func (db *Database) RevokeCertificate(filter CSRFilter) error {
	oldRow, err := db.GetCertificateRequest(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR_ID:        oldRow.CSR_ID,
		CSR:           oldRow.CSR,
		CertificateID: 0,
		Status:        "Revoked",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// DeleteCertificateRequest removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCertificateRequest(filter CSRFilter) error {
	var csrRow CertificateRequest

	switch {
	case filter.ID != nil:
		csrRow = CertificateRequest{CSR_ID: *filter.ID}
	case filter.PEM != nil:
		csrRow = CertificateRequest{CSR: *filter.PEM}
	default:
		return fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, csrRow).Run()
	return err
}
