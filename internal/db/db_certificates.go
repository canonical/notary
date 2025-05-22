package db

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/canonical/sqlair"
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificates() ([]Certificate, error) {
	certs, err := ListEntities[Certificate](db, db.stmts.ListCertificates)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list certificates", err)
	}
	return certs, nil
}

// GetCertificateByID gets a certificate row from the repository from a given ID.
func (db *Database) GetCertificate(filter CertificateFilter) (*Certificate, error) {
	certRow, err := filter.AsCertificate()
	if err != nil {
		return nil, err
	}

	cert, err := GetOneEntity[Certificate](db, db.stmts.GetCertificate, *certRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "certificate")
		}
		return nil, fmt.Errorf("%w: failed to get certificate", err)
	}
	return cert, nil
}

// AddCertificateChainToCertificateRequestByCSR adds a new certificate chain to a row for a given CSR string.
func (db *Database) AddCertificateChainToCertificateRequest(csrFilter CSRFilter, certPEM string) (int64, error) {
	csr, err := db.GetCertificateRequest(csrFilter)
	if err != nil {
		return 0, err
	}
	err = ValidateCertificate(certPEM)
	if err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidCertificate, err)
	}
	err = CertificateMatchesCSR(certPEM, csr.CSR)
	if err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidCertificate, err)
	}
	certBundle, err := SplitCertificateBundle(certPEM)
	if err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidCertificate, err)
	}
	var parentID int64 = 0
	if isSelfSigned(certBundle) {
		certRow := Certificate{
			IssuerID:       0,
			CertificatePEM: certBundle[0],
		}
		// Create the certificate
		var outcome sqlair.Outcome
		err = db.conn.Query(context.Background(), db.stmts.CreateCertificate, certRow).Get(&outcome)
		if err != nil {
			if IsConstraintError(err, "UNIQUE constraint failed") {
				return 0, fmt.Errorf("%w: certificate already exists", ErrAlreadyExists)
			}
			return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
		}
		childID, err := outcome.Result().LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
		}
		parentID = childID
	} else {
		// Otherwise, go through the certificate chain in reverse and add certs as their parents
		for _, v := range slices.Backward(certBundle) {
			certRow := Certificate{
				IssuerID:       parentID,
				CertificatePEM: v,
			}
			err = db.conn.Query(context.Background(), db.stmts.GetCertificate, certRow).Get(&certRow)
			childID := certRow.CertificateID
			if err == sqlair.ErrNoRows {
				var outcome sqlair.Outcome
				err = db.conn.Query(context.Background(), db.stmts.CreateCertificate, certRow).Get(&outcome)
				if err != nil {
					if IsConstraintError(err, "UNIQUE constraint failed") {
						return 0, fmt.Errorf("%w: certificate already exists", ErrAlreadyExists)
					}
					return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
				}
				childID, err = outcome.Result().LastInsertId()
				if err != nil {
					return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
				}
			} else if err != nil {
				return 0, fmt.Errorf("%w: failed to get certificate", ErrInternal)
			}
			parentID = childID
		}
	}
	newRow := CertificateRequest{
		CSR:           csr.CSR,
		CertificateID: parentID,
		Status:        "Active",
	}
	err = db.conn.Query(context.Background(), db.stmts.UpdateCertificateRequest, newRow).Run()
	if err != nil {
		return 0, fmt.Errorf("%w: failed to add certificate chain to certificate request", ErrInternal)
	}
	return parentID, nil
}

// DeleteCertificate removes a certificate from the database.
func (db *Database) DeleteCertificate(filter CertificateFilter) error {
	certRow, err := db.GetCertificate(filter)
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), db.stmts.DeleteCertificate, certRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete certificate", ErrInternal)
	}
	return nil
}

// GetCertificateChainByID gets a certificate chain row from the repository from a given ID.
func (db *Database) GetCertificateChain(filter CertificateFilter) ([]Certificate, error) {
	certRow, err := db.GetCertificate(filter)
	if err != nil {
		return nil, err
	}
	var certChain []Certificate
	err = db.conn.Query(context.Background(), db.stmts.GetCertificateChain, *certRow).GetAll(&certChain)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate chain not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to get certificate chain", ErrInternal)
	}
	return certChain, nil
}

func isSelfSigned(certBundle []string) bool {
	return len(certBundle) == 2 && certBundle[0] == certBundle[1]
}
