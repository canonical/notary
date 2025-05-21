package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequests() ([]CertificateRequest, error) {
	csrs, err := ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequests)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestsWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestsWithoutCAS() ([]CertificateRequest, error) {
	csrs, err := ListEntities[CertificateRequest](db, db.stmts.ListCertificateRequestsWithoutCAS)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestWithCertificates gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificates() ([]CertificateRequestWithChain, error) {
	csrs, err := ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithChain)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list certificate requests", err)
	}
	return csrs, nil
}

// ListCertificateRequestWithCertificatesWithoutCAS gets every CertificateRequest entry in the table.
func (db *Database) ListCertificateRequestWithCertificatesWithoutCAS() ([]CertificateRequestWithChain, error) {
	csrs, err := ListEntities[CertificateRequestWithChain](db, db.stmts.ListCertificateRequestsWithoutChain)
	if err != nil {
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

	csr, err := GetOneEntity[CertificateRequest](db, db.stmts.GetCertificateRequest, csrRow)
	if err != nil {
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

	err := db.conn.Query(context.Background(), db.stmts.GetCertificateRequestWithChain, csrRow).Get(&csrRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate request not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to get certificate request", ErrInternal)
	}
	return &csrRow, nil
}

// CreateCertificateRequest creates a new CSR entry in the repository. The string must be a valid CSR and unique.
func (db *Database) CreateCertificateRequest(csr string) (int64, error) {
	if err := ValidateCertificateRequest(csr); err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidCertificateRequest, err)
	}
	row := CertificateRequest{
		CSR: csr,
	}
	var outcome sqlair.Outcome
	err := db.conn.Query(context.Background(), db.stmts.CreateCertificateRequest, row).Get(&outcome)
	if err != nil {
		if IsConstraintError(err, "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: certificate request already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create certificate request", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
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
	newRow := CertificateRequest{
		CSR_ID:        oldRow.CSR_ID,
		CSR:           oldRow.CSR,
		CertificateID: 0,
		Status:        "Rejected",
	}
	err = db.conn.Query(context.Background(), db.stmts.UpdateCertificateRequest, newRow).Run()
	if err != nil {
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

	err = db.conn.Query(context.Background(), db.stmts.DeleteCertificateRequest, csrRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete certificate request", ErrInternal)
	}
	return nil
}
