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
		return nil, err
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
		return nil, err
	}
	return cert, nil
}

// DeleteCertificate removes a certificate from the database.
func (db *Database) DeleteCertificate(filter CertificateFilter) error {
	certRow, err := filter.AsCertificate()
	if err != nil {
		return err
	}
	err = DeleteEntity(db, db.stmts.DeleteCertificate, certRow)
	if err != nil {
		return err
	}
	return nil
}

// AddCertificateChainToCertificateRequestByCSR adds a new certificate chain to a row for a given CSR string.
func (db *Database) AddCertificateChainToCertificateRequest(csrFilter CSRFilter, certPEM string) (int64, error) {
	csr, err := db.GetCertificateRequest(csrFilter)
	if err != nil {
		return 0, err
	}
	err = ValidateCertificate(certPEM)
	if err != nil {
		return 0, err
	}
	err = CertificateMatchesCSR(certPEM, csr.CSR)
	if err != nil {
		return 0, err
	}
	certBundle, err := SplitCertificateBundle(certPEM)
	if err != nil {
		return 0, err
	}
	var parentID int64 = 0
	if isSelfSigned(certBundle) {
		certRow := Certificate{
			IssuerID:       0,
			CertificatePEM: certBundle[0],
		}
		// Create the certificate
		childID, err := CreateEntity(db, db.stmts.CreateCertificate, certRow)
		if err != nil {
			return 0, err
		}
		parentID = childID
	} else {
		// Otherwise, go through the certificate chain in reverse and add certs as their parents
		for _, v := range slices.Backward(certBundle) {
			certRow := Certificate{
				IssuerID:       parentID,
				CertificatePEM: v,
			}
			// TODO: use GetEntity here instead
			err = db.conn.Query(context.Background(), db.stmts.GetCertificate, certRow).Get(&certRow)
			childID := certRow.CertificateID
			if err == sqlair.ErrNoRows {
				var outcome sqlair.Outcome
				// TODO: use CreateEntity here instead
				err = db.conn.Query(context.Background(), db.stmts.CreateCertificate, certRow).Get(&outcome)
				if err != nil {
					return 0, HandleDBCreateQueryError(err, "certificate")
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
	err = UpdateEntity(db, db.stmts.UpdateCertificateRequest, newRow)
	if err != nil {
		return 0, err
	}
	return parentID, nil
}

// GetCertificateChainByID gets a certificate chain row from the repository from a given ID.
func (db *Database) GetCertificateChain(filter CertificateFilter) ([]Certificate, error) {
	certRow, err := filter.AsCertificate()
	if err != nil {
		return nil, err
	}
	var certChain []Certificate
	// TODO: use ListEntities here instead, and convert all generic functions to variadic
	err = db.conn.Query(context.Background(), db.stmts.GetCertificateChain, *certRow).GetAll(&certChain)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate chain not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to get certificate chain", ErrInternal)
	}
	return certChain, nil
}
