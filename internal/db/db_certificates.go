package db

import (
	"context"
	"errors"
	"fmt"
	"log"
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

var ErrInvalidCertificate = errors.New("invalid certificate")

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificates() ([]Certificate, error) {
	certs, err := ListEntities[Certificate](db, listCertificatesStmt)
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to list certificates", ErrInternal)
	}
	return certs, nil
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
		return nil, InvalidFilterError("certificate", "both ID and PEM are nil")
	}

	cert, err := GetOneEntity[Certificate](db, getCertificateStmt, certRow)
	if err != nil {
		log.Println(err)
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, NotFoundError("certificate")
		}
		return nil, fmt.Errorf("%w: failed to get certificate", ErrInternal)
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
		return 0, ErrInvalidCertificate
	}
	err = CertificateMatchesCSR(certPEM, csr.CSR)
	if err != nil {
		return 0, ErrInvalidCertificate
	}
	certBundle, err := sanitizeCertificateBundle(certPEM)
	if err != nil {
		return 0, ErrInvalidCertificate
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
			log.Println(err)
			return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
		}
		var outcome sqlair.Outcome
		err = db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
		if err != nil {
			if isUniqueConstraintError(err) {
				return 0, fmt.Errorf("%w: certificate already exists", ErrAlreadyExists)
			}
			log.Println(err)
			return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
		}
		childID, err := outcome.Result().LastInsertId()
		if err != nil {
			log.Println(err)
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
			stmt, err := sqlair.Prepare(getCertificateStmt, Certificate{})
			if err != nil {
				log.Println(err)
				return 0, fmt.Errorf("%w: failed to get certificate", ErrInternal)
			}
			err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
			childID := certRow.CertificateID
			if err == sqlair.ErrNoRows {
				stmt, err = sqlair.Prepare(createCertificateStmt, Certificate{})
				if err != nil {
					log.Println(err)
					return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
				}
				var outcome sqlair.Outcome
				err = db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
				if err != nil {
					if isUniqueConstraintError(err) {
						return 0, fmt.Errorf("%w: certificate already exists", ErrAlreadyExists)
					}
					log.Println(err)
					return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
				}
				childID, err = outcome.Result().LastInsertId()
				if err != nil {
					log.Println(err)
					return 0, fmt.Errorf("%w: failed to create certificate", ErrInternal)
				}
			} else if err != nil {
				log.Println(err)
				return 0, fmt.Errorf("%w: failed to get certificate", ErrInternal)
			}
			parentID = childID
		}
	}
	stmt, err := sqlair.Prepare(updateCertificateRequestStmt, CertificateRequest{})
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to add certificate chain to certificate request", ErrInternal)
	}
	newRow := CertificateRequest{
		CSR:           csr.CSR,
		CertificateID: parentID,
		Status:        "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to add certificate chain to certificate request", ErrInternal)
	}
	return parentID, nil
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
		return InvalidFilterError("certificate", "both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(deleteCertificateStmt, Certificate{})
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to delete certificate", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, certRow).Run()
	if err != nil {
		log.Println(err)
		if errors.Is(err, sqlair.ErrNoRows) {
			return fmt.Errorf("%w: certificate not found", ErrNotFound)
		}
		return fmt.Errorf("%w: failed to delete certificate", ErrInternal)
	}
	return nil
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
		return nil, InvalidFilterError("certificate", "both ID and PEM are nil")
	}

	stmt, err := sqlair.Prepare(getCertificateChainStmt, Certificate{})
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to get certificate chain", ErrInternal)
	}
	var certChain []Certificate
	err = db.conn.Query(context.Background(), stmt, certRow).GetAll(&certChain)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate chain not found", ErrNotFound)
		}
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to get certificate chain", ErrInternal)
	}
	return certChain, nil
}

func isSelfSigned(certBundle []string) bool {
	return len(certBundle) == 2 && certBundle[0] == certBundle[1]
}
