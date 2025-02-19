package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

type CAStatus string

func (ca CAStatus) String() string {
	return string(ca)
}

func (ca CAStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(ca.String())
}

const (
	CAActive  CAStatus = "active"
	CAExpired CAStatus = "expired"
	CAPending CAStatus = "pending"
	CALegacy  CAStatus = "legacy"
)

func NewStatusFromString(s string) (CAStatus, error) {
	statuses := map[CAStatus]struct{}{
		CAActive:  {},
		CAExpired: {},
		CAPending: {},
		CALegacy:  {},
	}

	status := CAStatus(s)
	_, ok := statuses[status]
	if !ok {
		return "", fmt.Errorf("invalid status: status must be one of %s, %s, %s, %s", CAActive, CAExpired, CAPending, CALegacy)
	}
	return status, nil
}

type CertificateAuthority struct {
	CertificateAuthorityID int64 `db:"certificate_authority_id"`

	Status CAStatus `db:"status"`

	PrivateKeyID  int64 `db:"private_key_id"`
	CertificateID int64 `db:"certificate_id"`
	CSRID         int64 `db:"csr_id"`
}

type CertificateAuthorityDenormalized struct {
	CertificateAuthorityID int64    `db:"certificate_authority_id"`
	Status                 CAStatus `db:"status"`
	PrivateKeyPEM          string   `db:"private_key"`
	CertificatePEM         string   `db:"certificate"`
	CSRPEM                 string   `db:"csr"`
}

const queryCreateCertificateAuthoritiesTable = `
	CREATE TABLE IF NOT EXISTS certificate_authorities (
	    certificate_authority_id INTEGER PRIMARY KEY AUTOINCREMENT,

		status TEXT DEFAULT 'Pending', 

		private_key_id INTEGER,
		certificate_id INTEGER,
		csr_id INTEGER NOT NULL UNIQUE,

		CHECK (status IN ('active', 'expired', 'pending', 'legacy')),
		CHECK (NOT (certificate_id == NULL AND status == 'active' )),
		CHECK (NOT (certificate_id != NULL AND status == 'pending'))
        CHECK (NOT (certificate_id != NULL AND status == 'expired'))
)`

const (
	createCertificateAuthorityStmt = "INSERT INTO certificate_authorities (status, private_key_id, csr_id, certificate_id) VALUES ($CertificateAuthority.status, $CertificateAuthority.private_key_id, $CertificateAuthority.csr_id, $CertificateAuthority.certificate_id)"
	getCertificateAuthorityStmt    = "SELECT &CertificateAuthority.* FROM certificate_authorities WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id"
	listCertificateAuthoritiesStmt = "SELECT &CertificateAuthority.* FROM certificate_authorities"
	updateCertificateAuthorityStmt = "UPDATE certificate_authorities SET status=$CertificateAuthority.status, certificate_id=$CertificateAuthority.certificate_id WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id"
	deleteCertificateAuthorityStmt = "DELETE FROM certificate_authorities WHERE certificate_authority_id=$CertificateAuthority.certificate_authority_id or csr_id=$CertificateAuthority.csr_id"

	listDenormalizedCertificateAuthoritiesStmt = `
	SELECT 
		ca.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		ca.status as &CertificateAuthorityDenormalized.status,
		pk.private_key AS &CertificateAuthorityDenormalized.private_key,
		cert.certificate AS &CertificateAuthorityDenormalized.certificate,
		csr.csr AS &CertificateAuthorityDenormalized.csr
	FROM certificate_authorities ca
	LEFT JOIN certificates cert ON ca.certificate_id = cert.certificate_id
	LEFT JOIN certificate_requests csr ON ca.csr_id = csr.csr_id
	LEFT JOIN private_keys pk ON ca.private_key_id = pk.private_key_id
	`
	getDenormalizedCertificateAuthorityStmt = `
	SELECT 
		ca.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		ca.status as &CertificateAuthorityDenormalized.status,
		pk.private_key AS &CertificateAuthorityDenormalized.private_key,
		cert.certificate AS &CertificateAuthorityDenormalized.certificate,
		csr.csr AS &CertificateAuthorityDenormalized.csr
	FROM certificate_authorities ca
	LEFT JOIN certificates cert ON ca.certificate_id = cert.certificate_id
	LEFT JOIN certificate_requests csr ON ca.csr_id = csr.csr_id
	LEFT JOIN private_keys pk ON ca.private_key_id = pk.private_key_id
	WHERE ca.certificate_authority_id==$CertificateAuthority.certificate_authority_id or ca.csr_id==$CertificateAuthority.csr_id or csr.csr==$CertificateAuthorityDenormalized.csr
	`
)

// ListCertificateAuthorities gets every Certificate Authority entry in the table.
func (db *Database) ListCertificateAuthorities() ([]CertificateAuthority, error) {
	stmt, err := sqlair.Prepare(listCertificateAuthoritiesStmt, CertificateAuthority{})
	if err != nil {
		return nil, err
	}
	var CAs []CertificateAuthority
	err = db.conn.Query(context.Background(), stmt).GetAll(&CAs)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return CAs, nil
		}
		return nil, err
	}
	return CAs, nil
}

// ListDenormalizedCertificateAuthorities gets every CertificateAuthority entry in the table
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) ListDenormalizedCertificateAuthorities() ([]CertificateAuthorityDenormalized, error) {
	stmt, err := sqlair.Prepare(listDenormalizedCertificateAuthoritiesStmt, CertificateAuthorityDenormalized{})
	if err != nil {
		return nil, err
	}
	var CAs []CertificateAuthorityDenormalized
	err = db.conn.Query(context.Background(), stmt).GetAll(&CAs)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return CAs, nil
		}
		return nil, err
	}
	return CAs, nil
}

// GetCertificateAuthority gets a certificate authority row from the database.
func (db *Database) GetCertificateAuthority(filter CertificateAuthorityFilter) (*CertificateAuthority, error) {
	CARow, err := filter.AsCertificateAuthority()
	if err != nil {
		return nil, err
	}
	stmt, err := sqlair.Prepare(getCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, CARow).Get(CARow)
	if err != nil {
		return nil, err
	}
	return CARow, nil
}

// GetDenormalizedCertificateAuthority gets a certificate authority row from the database
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) GetDenormalizedCertificateAuthority(filter CertificateAuthorityFilter) (*CertificateAuthorityDenormalized, error) {
	CADenormalizedRow, DenormalizedCAErr := filter.AsCertificateAuthorityDenormalized()
	CARow, CAerr := filter.AsCertificateAuthority()
	if CAerr != nil && DenormalizedCAErr != nil {
		return nil, fmt.Errorf("invalid filter: only CA ID, CSR ID, or CSR PEM is supported")
	}
	stmt, err := sqlair.Prepare(getDenormalizedCertificateAuthorityStmt, CertificateAuthority{}, CertificateAuthorityDenormalized{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, CARow, CADenormalizedRow).Get(CADenormalizedRow)
	if err != nil {
		return nil, err
	}
	return CADenormalizedRow, nil
}

// CreateCertificateAuthority creates a new certificate authority in the database from a given CSR, private key, and certificate chain.
// The certificate chain is optional and can be empty.
func (db *Database) CreateCertificateAuthority(csrPEM string, privPEM string, certChainPEM string) (int64, error) {
	csrID, err := db.CreateCertificateRequest(csrPEM)
	if err != nil {
		return 0, err
	}
	pkID, err := db.CreatePrivateKey(privPEM)
	if err != nil {
		return 0, err
	}
	CARow := CertificateAuthority{
		CSRID:        csrID,
		PrivateKeyID: pkID,
		Status:       CAPending,
	}
	if certChainPEM != "" {
		certID, err := db.AddCertificateChainToCertificateRequest(ByCSRID(csrID), certChainPEM)
		if err != nil {
			return 0, err
		}
		CARow = CertificateAuthority{
			CSRID:         csrID,
			CertificateID: certID,
			PrivateKeyID:  pkID,
			Status:        CAActive,
		}
	}
	stmt, err := sqlair.Prepare(createCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return 0, err
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, CARow).Get(&outcome)
	if err != nil {
		return 0, err
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, err
	}
	return insertedRowID, nil
}

// UpdateCertificateAuthorityCertificate updates the certificate chain associated with a certificate authority.
func (db *Database) UpdateCertificateAuthorityCertificate(filter CertificateAuthorityFilter, certChainPEM string) error {
	ca, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	certID, err := db.AddCertificateChainToCertificateRequest(ByCSRID(ca.CSRID), certChainPEM)
	if err != nil {
		return err
	}
	ca.CertificateID = certID
	ca.Status = CAActive

	stmt, err := sqlair.Prepare(updateCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, ca).Run()
	return err
}

// UpdateCertificateAuthorityStatus updates the status of a certificate authority.
func (db *Database) UpdateCertificateAuthorityStatus(filter CertificateAuthorityFilter, status CAStatus) error {
	ca, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	ca.Status = status
	stmt, err := sqlair.Prepare(updateCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, ca).Run()
	return err
}

// DeleteCertificateAuthority removes a certificate authority from the database.
func (db *Database) DeleteCertificateAuthority(filter CertificateAuthorityFilter) error {
	caRow, err := filter.AsCertificateAuthority()
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(deleteCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, caRow).Run()
	return err
}
