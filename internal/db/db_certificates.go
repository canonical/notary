package db

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/canonical/sqlair"
)

type Certificate struct {
	CertificateID int64 `db:"certificate_id"`
	IssuerID      int64 `db:"issuer_id"` // if the issuer id == certificate_id, then this is a self-signed certificate

	CertificatePEM string `db:"certificate"`
}

const queryCreateCertificatesTable = `
	CREATE TABLE IF NOT EXISTS certificates (
	    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,
		issuer_id INTEGER,

		certificate TEXT NOT NULL UNIQUE
)`

const (
	createCertificateStmt   = "INSERT INTO certificates (certificate, issuer_id) VALUES ($Certificate.certificate, $Certificate.issuer_id)"
	addCertificateToCSRStmt = "UPDATE certificates SET certificate_id=$Certificate.certificate_id, status=$CertificateRequest.status WHERE id==$CertificateRequest.id or csr==$CertificateRequest.csr"
	getCertificateStmt      = "SELECT &Certificate.* FROM certificates WHERE certificate_id==$Certificate.certificate_id or certificate==$Certificate.certificate"
	updateCertificateStmt   = "UPDATE certificates SET issuer_id=$Certificate.issuer_id WHERE certificate_id==$Certificate.certificate_id or certificate==$Certificate.certificate"
	listCertificatesStmt    = "SELECT &Certificate.* FROM certificates"
	deleteCertificateStmt   = "DELETE FROM certificates WHERE certificate_id=$Certificate.certificate_id or certificate=$Certificate.certificate"

	getCertificateChainStmt = `WITH RECURSIVE cert_chain AS (
    -- Initial query: Start search from the end certificate
    SELECT certificate_id, certificate, issuer_id
    FROM certificates
    WHERE certificate_id = $Certificate.certificate_id or certificate = $Certificate.certificate
    
    UNION ALL
    
    -- Recursive Query: Move up the chain until issuer_id is 0 (root)
    SELECT certs.certificate_id, certs.certificate, certs.issuer_id
    FROM certificates certs
    JOIN cert_chain
      ON certs.certificate_id = cert_chain.issuer_id
)
SELECT &Certificate.* FROM cert_chain;`
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificates() ([]Certificate, error) {
	stmt, err := sqlair.Prepare(listCertificatesStmt, Certificate{})
	if err != nil {
		return nil, err
	}
	var certificates []Certificate
	err = db.conn.Query(context.Background(), stmt).GetAll(&certificates)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return certificates, nil
		}
		return nil, err
	}
	return certificates, nil
}

// GetCertificateByID gets a certificate row from the repository from a given ID.
func (db *Database) GetCertificate(filter CertificateFilter) (*Certificate, error) {
	var certRow Certificate

	switch {
	case filter.ID != nil:
		certRow = Certificate{CertificateID: *filter.ID}
	case filter.PEM != nil:
		certRow = Certificate{CertificatePEM: *filter.PEM}
	default:
		return nil, fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(getCertificateStmt, Certificate{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
	if err != nil {
		return nil, err
	}
	return &certRow, nil
}

// AddCertificateChainToCertificateRequestByCSR adds a new certificate chain to a row for a given CSR string.
func (db *Database) AddCertificateChainToCertificateRequest(csrFilter CSRFilter, certPEM string) error {
	csr, err := db.GetCertificateRequest(csrFilter)
	if err != nil {
		return err
	}
	err = ValidateCertificate(certPEM)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	err = CertificateMatchesCSR(certPEM, csr.CSR)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	certBundle, err := sanitizeCertificateBundle(certPEM)
	if err != nil {
		return errors.New("cert validation failed: " + err.Error())
	}
	var parentID int64 = 0
	if isSelfSigned(certBundle) {
		certRow := Certificate{
			IssuerID:       0,
			CertificatePEM: certBundle[0],
		}
		// Create the certificate
		stmt, err := sqlair.Prepare(createCertificateStmt, Certificate{})
		if err != nil {
			return err
		}
		var outcome sqlair.Outcome
		err = db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
		if err != nil {
			return err
		}
		childID, err := outcome.Result().LastInsertId()
		if err != nil {
			return err
		}
		parentID = childID
	} else {
		// Otherwise, go through the certificate chain in reverse and add certs as their parents
		for _, v := range slices.Backward(certBundle) {
			certRow := Certificate{
				IssuerID:       parentID,
				CertificatePEM: v,
			}
			stmt, err := sqlair.Prepare(getCertificateStmt, Certificate{})
			if err != nil {
				return err
			}
			err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
			childID := certRow.CertificateID
			if err == sqlair.ErrNoRows {
				stmt, err = sqlair.Prepare(createCertificateStmt, Certificate{})
				if err != nil {
					return err
				}
				var outcome sqlair.Outcome
				err = db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
				if err != nil {
					return err
				}
				childID, err = outcome.Result().LastInsertId()
				if err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			parentID = childID
		}
	}
	stmt, err := sqlair.Prepare(updateCertificateRequestStmt, CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR:           csr.CSR,
		CertificateID: parentID,
		Status:        "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// DeleteCertificate removes a certificate from the database.
func (db *Database) DeleteCertificate(filter CertificateFilter) error {
	var certRow Certificate

	switch {
	case filter.ID != nil:
		certRow = Certificate{CertificateID: *filter.ID}
	case filter.PEM != nil:
		certRow = Certificate{CertificatePEM: *filter.PEM}
	default:
		return fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(deleteCertificateStmt, Certificate{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, certRow).Run()
	return err
}

// GetCertificateChainByID gets a certificate chain row from the repository from a given ID.
func (db *Database) GetCertificateChain(filter CertificateFilter) ([]Certificate, error) {
	var certRow Certificate

	switch {
	case filter.ID != nil:
		certRow = Certificate{CertificateID: *filter.ID}
	case filter.PEM != nil:
		certRow = Certificate{CertificatePEM: *filter.PEM}
	default:
		return nil, fmt.Errorf("invalid certificate identifier: both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(getCertificateChainStmt, Certificate{})
	if err != nil {
		return nil, err
	}
	var certChain []Certificate
	err = db.conn.Query(context.Background(), stmt, certRow).GetAll(&certChain)
	if err != nil {
		return nil, err
	}
	return certChain, nil
}

func isSelfSigned(certBundle []string) bool {
	return len(certBundle) == 2 && certBundle[0] == certBundle[1]
}
