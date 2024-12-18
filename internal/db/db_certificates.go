package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type Certificate struct {
	CertificateID int `db:"certificate_id"`

	Issuer       int `db:"issuer_id"`      // if the issuer id == certificate_id, then this is a self-signed certificate
	PrivateKeyID int `db:"private_key_id"` // if there is no private key, then this certificate cannot sign CSR's

	CertificatePEM string `db:"certificate"`
}

type PrivateKey struct {
	ID int `db:"private_key_id"`

	PrivateKey string `db:"private_key"`
}

const queryCreateCertificatesTable = `
	CREATE TABLE IF NOT EXISTS %s (
	    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,

		issuer_id INTEGER,
		private_key_id INTEGER,

		certificate TEXT NOT NULL UNIQUE
)`

const (
	createCertificateStmt    = "INSERT INTO %s (certificate, private_key_id, issuer_id) VALUES ($Certificate.certificate, $Certificate.private_key_id, $Certificate.issuer_id)"
	addCertificateToCSRsStmt = "UPDATE %s SET certificate_id=$Certificate.certificate_id, status=$CertificateRequest.status WHERE id==$CertificateRequest.id or csr==$CertificateRequest.csr"
	getCertificateStmt       = "SELECT &Certificate.* FROM %s WHERE certificate_id==$Certificate.certificate_id or certificate==$Certificate.certificate"
	listCertificatesStmt     = "SELECT &Certificate.* FROM %s"
	deleteCertificateStmt    = "DELETE FROM %s WHERE certificate_id=$Certificate.certificate_id or certificate=$Certificate.certificate"

	getCertificateChainStmt = `WITH RECURSIVE cert_chain AS (
	-- Initial query: Start search from the end certificate
    SELECT certificate_id, certificate, issuer_id
    FROM %s
    WHERE certificate_id = $Certificate.certificate_id or certificate = $Certificate.certificate
    
    UNION ALL
    
    -- Recursive Query: Move up the chain until issuer_id is 0 (root)
    SELECT certs.certificate_id, certs.certificate, certs.issuer_id
    FROM certificates certs
    JOIN cert_chain
      ON certs.certificate_id = cert_chain.issuer_id
)
SELECT * FROM cert_chain;`
)

// ListCertificateRequests gets every CertificateRequest entry in the table.
func (db *Database) ListCertificates() ([]Certificate, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(listCertificatesStmt, db.certificatesTable), Certificate{})
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
func (db *Database) GetCertificateByID(id int) (*Certificate, error) {
	certRow := Certificate{
		CertificateID: id,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateStmt, db.certificatesTable), Certificate{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
	if err != nil {
		return nil, err
	}
	return &certRow, nil
}

// GetCertificateByID gets a certificate row from the repository from a given ID.
func (db *Database) GetCertificateByCertificatePEM(cert string) (*Certificate, error) {
	certRow := Certificate{
		CertificatePEM: cert,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateStmt, db.certificatesTable), Certificate{})
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
func (db *Database) AddCertificateChainToCertificateRequestByCSR(csrPEM string, certPEM string) error {
	csr, err := db.GetCertificateRequestByCSR(csrPEM)
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
	parentID := 0
	for i := len(certBundle) - 1; i >= 0; i-- {
		certRow := Certificate{
			Issuer:         parentID,
			PrivateKeyID:   0,
			CertificatePEM: certBundle[i],
		}
		stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateStmt, db.certificatesTable), Certificate{})
		if err != nil {
			return err
		}
		err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
		childID := int64(certRow.CertificateID)
		if err == sqlair.ErrNoRows {
			stmt, err = sqlair.Prepare(fmt.Sprintf(createCertificateStmt, db.certificatesTable), Certificate{})
			if err != nil {
				return err
			}
			var outcome sqlair.Outcome
			db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
			childID, err = outcome.Result().LastInsertId()
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		parentID = int(childID)
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR:           csrPEM,
		CertificateID: parentID,
		Status:        "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// AddCertificateChainToCSRbyID adds a new certificate chain to a row for a given row ID.
func (db *Database) AddCertificateChainToCertificateRequestByID(id int, certPEM string) error {
	csr, err := db.GetCertificateRequestByID(id)
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
	parentID := 0
	for i := len(certBundle) - 1; i >= 0; i-- {
		certRow := Certificate{
			Issuer:         parentID,
			PrivateKeyID:   0,
			CertificatePEM: certBundle[i],
		}
		stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateStmt, db.certificatesTable), Certificate{})
		if err != nil {
			return err
		}
		err = db.conn.Query(context.Background(), stmt, certRow).Get(&certRow)
		childID := int64(certRow.CertificateID)
		if err == sqlair.ErrNoRows {
			stmt, err = sqlair.Prepare(fmt.Sprintf(createCertificateStmt, db.certificatesTable), Certificate{})
			if err != nil {
				return err
			}
			var outcome sqlair.Outcome
			db.conn.Query(context.Background(), stmt, certRow).Get(&outcome)
			childID, err = outcome.Result().LastInsertId()
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		parentID = int(childID)
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	newRow := CertificateRequest{
		CSR_ID:        id,
		CertificateID: parentID,
		Status:        "Active",
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

// DeleteCertificateRequestByCSR removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCertificateByCertificate(certPEM string) error {
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := Certificate{
		CertificatePEM: certPEM,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// DeleteCSRByID removes a CSR from the database alongside the certificate that may have been generated for it.
func (db *Database) DeleteCertificateByID(id int) error {
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteCertificateRequestStmt, db.certificateRequestsTable), CertificateRequest{})
	if err != nil {
		return err
	}
	row := Certificate{
		CertificateID: id,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// GetCertificateChainByID gets a certificate chain row from the repository from a given ID.
func (db *Database) GetCertificateChainByID(id int) ([]Certificate, error) {
	var certChain []Certificate
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateChainStmt, db.certificatesTable), CertificateRequestWithChain{})
	if err != nil {
		return nil, err
	}
	row := Certificate{
		CertificateID: id,
	}
	err = db.conn.Query(context.Background(), stmt, row).GetAll(&certChain)
	if err != nil {
		return nil, err
	}
	return certChain, nil
}

// GetCertificateChainByCSR gets a given CSR row from the repository using the CSR text.
func (db *Database) GetCertificateChainByCertificate(cert string) ([]Certificate, error) {
	var certChain []Certificate
	stmt, err := sqlair.Prepare(fmt.Sprintf(getCertificateChainStmt, db.certificatesTable), CertificateRequestWithChain{})
	if err != nil {
		return nil, err
	}
	row := Certificate{
		CertificatePEM: cert,
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&certChain)
	if err != nil {
		return nil, err
	}
	return certChain, nil
}
