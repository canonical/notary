package db

import (
	"errors"
	"fmt"
	"slices"
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificates() ([]Certificate, error) {
	return ListEntities[Certificate](db, db.stmts.ListCertificates)
}

// GetCertificateByID gets a certificate row from the repository from a given ID.
func (db *Database) GetCertificate(filter CertificateFilter) (*Certificate, error) {
	certRow := filter.AsCertificate()
	return GetOneEntity[Certificate](db, db.stmts.GetCertificate, *certRow)
}

// DeleteCertificate removes a certificate from the database.
func (db *Database) DeleteCertificate(filter CertificateFilter) error {
	certRow := filter.AsCertificate()
	return DeleteEntity(db, db.stmts.DeleteCertificate, certRow)
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
			cert, err := GetOneEntity[Certificate](db, db.stmts.GetCertificate, certRow)
			var childID int64
			if errors.Is(err, ErrNotFound) {
				id, err := CreateEntity(db, db.stmts.CreateCertificate, certRow)
				childID = id
				if err != nil {
					return 0, fmt.Errorf("%w: %w: failed to create certificate", ErrInternal, err)
				}
			} else if err != nil {
				return 0, fmt.Errorf("%w: %w: failed to get certificate", ErrInternal, err)
			} else {
				childID = cert.CertificateID
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
	certRow := filter.AsCertificate()
	certChain, err := ListEntities[Certificate](db, db.stmts.GetCertificateChain, *certRow)
	if err != nil {
		return nil, err
	}
	if len(certChain) == 0 {
		return nil, fmt.Errorf("%w: certificate chain not found", ErrNotFound)
	}
	return certChain, nil
}
