package db

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/canonical/sqlair"
)

type CertificateRequest struct {
	CSR_ID int64 `db:"csr_id"`

	CSR           string `db:"csr"`
	Status        string `db:"status"`
	CertificateID int64  `db:"certificate_id"`
}

type CertificateRequestWithChain struct {
	CSR_ID int64 `db:"csr_id"`

	CSR              string `db:"csr"`
	Status           string `db:"status"`
	CertificateChain string `db:"certificate_chain"`
}

const queryCreateCertificateRequestsTable = `
	CREATE TABLE IF NOT EXISTS certificate_requests (
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
	listCertificateRequestsStmt           = "SELECT &CertificateRequest.* FROM certificate_requests"
	listCertificateRequestsWithoutCASStmt = "SELECT csrs.&CertificateRequest.csr_id, csrs.&CertificateRequest.csr, csrs.&CertificateRequest.status, csrs.&CertificateRequest.certificate_id FROM certificate_requests csrs LEFT JOIN certificate_authorities cas ON csrs.csr_id = cas.csr_id WHERE cas.certificate_authority_id IS NULL"
	getCertificateRequestStmt             = "SELECT &CertificateRequest.* FROM certificate_requests WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	updateCertificateRequestStmt          = "UPDATE certificate_requests SET certificate_id=$CertificateRequest.certificate_id, status=$CertificateRequest.status WHERE csr_id==$CertificateRequest.csr_id or csr==$CertificateRequest.csr"
	createCertificateRequestStmt          = "INSERT INTO certificate_requests (csr) VALUES ($CertificateRequest.csr)"
	deleteCertificateRequestStmt          = "DELETE FROM certificate_requests WHERE csr_id=$CertificateRequest.csr_id or csr=$CertificateRequest.csr"

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
    FROM certificate_requests csr
    LEFT JOIN certificates cert 
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
    FROM certificates cert
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
	listCertificateRequestsWithCertificatesWithoutCASStmt = `
WITH RECURSIVE certificate_chain AS (
    SELECT 
        csr.csr_id,
        csr.csr,
		csr.status,
        cert.certificate_id,
        cert.issuer_id,
        cert.certificate,
        COALESCE(cert.certificate, '') AS chain
    FROM certificate_requests csr
    LEFT JOIN certificates cert 
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
    FROM certificates cert
    JOIN certificate_chain cc
      ON cert.certificate_id = cc.issuer_id
)
SELECT 
	cc.&CertificateRequestWithChain.csr_id,
	cc.&CertificateRequestWithChain.csr,
	cc.&CertificateRequestWithChain.status,
	chain AS &CertificateRequestWithChain.certificate_chain
FROM certificate_chain cc
LEFT JOIN certificate_authorities cas ON cc.csr_id = cas.csr_id 
WHERE cas.certificate_authority_id IS NULL AND (chain = '' OR issuer_id = 0)`

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
    FROM certificate_requests csr
    LEFT JOIN certificates cert 
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
    FROM certificates cert
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
	csrs, err := ListEntities[CertificateRequest](db, listCertificateRequestsStmt)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestsWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestsWithoutCAS() ([]CertificateRequest, error) {
	csrs, err := ListEntities[CertificateRequest](db, listCertificateRequestsWithoutCASStmt)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestWithCertificates gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificates() ([]CertificateRequestWithChain, error) {
	csrs, err := ListEntities[CertificateRequestWithChain](db, listCertificateRequestsWithCertificatesStmt)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestWithCertificatesWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificatesWithoutCAS() ([]CertificateRequestWithChain, error) {
	csrs, err := ListEntities[CertificateRequestWithChain](db, listCertificateRequestsWithCertificatesWithoutCASStmt)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
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
		return nil, fmt.Errorf("%w: certificate request - both ID and PEM are nil", ErrInvalidFilter)
	}

	csr, err := GetOneEntity[CertificateRequest](db, getCertificateRequestStmt, csrRow)
	if err != nil {
		log.Println(err)
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "certificate request")
		}
		return nil, fmt.Errorf("%w: failed to get certificate request", err)
	}
	return csr, nil
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
		return nil, fmt.Errorf("%w: certificate request - both ID and PEM are nil", ErrInvalidFilter)
	}

	stmt, err := sqlair.Prepare(getCertificateRequestWithCertificateStmt, CertificateRequestWithChain{})
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to get certificate request due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, csrRow).Get(&csrRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate request not found", ErrNotFound)
		}
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to get certificate request", ErrInternal)
	}
	return &csrRow, nil
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCertificateRequest(csr string) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidCertificateRequest, err)
	}
	stmt, err := sqlair.Prepare(createCertificateRequestStmt, CertificateRequest{})
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create certificate request due to sql compilation error", ErrInternal)
	}
	row := CertificateRequest{
		CSR: csr,
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, row).Get(&outcome)
	if err != nil {
		if IsConstraintError(err, "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: certificate request already exists", ErrAlreadyExists)
		}
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create certificate request", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create certificate request", ErrInternal)
	}
	return insertedRowID, nil
}

// RejectCertificateRequest updates input CSR's row by setting the certificate bundle to "" and moving the row status to "Rejected".
func (db *Database) RejectCertificateRequest(filter CSRFilter) error {
	oldRow, err := db.GetCertificateRequest(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(updateCertificateRequestStmt, CertificateRequest{})
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
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to reject certificate request", ErrInternal)
	}
	return nil
}

// DeleteCertificateRequest removes a CSR from the database.
func (db *Database) DeleteCertificateRequest(filter CSRFilter) error {
	csrRow, err := db.GetCertificateRequest(filter)
	if err != nil {
		return err
	}

	stmt, err := sqlair.Prepare(deleteCertificateRequestStmt, CertificateRequest{})
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to delete certificate request due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, csrRow).Run()
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to delete certificate request", ErrInternal)
	}
	return nil
}
