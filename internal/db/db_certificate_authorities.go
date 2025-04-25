package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/canonical/sqlair"
)

const expiryYears = 1

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

	CRL    string   `db:"crl"`
	Status CAStatus `db:"status"`

	PrivateKeyID  int64 `db:"private_key_id"`
	CertificateID int64 `db:"certificate_id"`
	CSRID         int64 `db:"csr_id"`
}

type CertificateAuthorityDenormalized struct {
	CertificateAuthorityID int64    `db:"certificate_authority_id"`
	CRL                    string   `db:"crl"`
	Status                 CAStatus `db:"status"`
	PrivateKeyPEM          string   `db:"private_key"`
	CertificateChain       string   `db:"certificate_chain"`
	CSRPEM                 string   `db:"csr"`
}

const queryCreateCertificateAuthoritiesTable = `
	CREATE TABLE IF NOT EXISTS certificate_authorities (
	    certificate_authority_id INTEGER PRIMARY KEY AUTOINCREMENT,

		crl TEXT,
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
	createCertificateAuthorityStmt = "INSERT INTO certificate_authorities (crl, status, private_key_id, csr_id, certificate_id) VALUES ($CertificateAuthority.crl, $CertificateAuthority.status, $CertificateAuthority.private_key_id, $CertificateAuthority.csr_id, $CertificateAuthority.certificate_id)"
	getCertificateAuthorityStmt    = "SELECT &CertificateAuthority.* FROM certificate_authorities WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id or certificate_id==$CertificateAuthority.certificate_id"
	listCertificateAuthoritiesStmt = "SELECT &CertificateAuthority.* FROM certificate_authorities"
	updateCertificateAuthorityStmt = "UPDATE certificate_authorities SET crl=$CertificateAuthority.crl, status=$CertificateAuthority.status, certificate_id=$CertificateAuthority.certificate_id WHERE certificate_authority_id==$CertificateAuthority.certificate_authority_id or csr_id==$CertificateAuthority.csr_id"
	deleteCertificateAuthorityStmt = "DELETE FROM certificate_authorities WHERE certificate_authority_id=$CertificateAuthority.certificate_authority_id or csr_id=$CertificateAuthority.csr_id"

	listDenormalizedCertificateAuthoritiesStmt = `
WITH RECURSIVE cas_with_chain AS (    
    SELECT 
        cas.certificate_authority_id,
        cas.private_key_id,
		cas.csr_id,
        cas.status,
        cas.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        COALESCE(certs.certificate, '') AS chain
    FROM certificate_authorities cas
    LEFT JOIN certificates certs ON cas.certificate_id = certs.certificate_id

    UNION ALL

    SELECT 
        cc.certificate_authority_id,
		cc.private_key_id,
		cc.csr_id,
        cc.status,
		cc.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        cc.chain || CHAR(10) || certs.certificate AS chain
    FROM cas_with_chain cc
    JOIN certificates certs ON certs.certificate_id = cc.issuer_id
)
	SELECT 
		cc.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		cc.crl as &CertificateAuthorityDenormalized.crl,
		cc.status as &CertificateAuthorityDenormalized.status,
		pk.private_key AS &CertificateAuthorityDenormalized.private_key,
		cc.chain AS &CertificateAuthorityDenormalized.certificate_chain,
		csrs.csr AS &CertificateAuthorityDenormalized.csr
	FROM cas_with_chain cc
	LEFT JOIN private_keys pk ON cc.private_key_id = pk.private_key_id
	LEFT JOIN certificate_requests csrs ON cc.csr_id = csrs.csr_id
	WHERE cc.chain = '' OR cc.issuer_id = 0
`
	getDenormalizedCertificateAuthorityStmt = `
WITH RECURSIVE cas_with_chain AS (    
    SELECT 
        cas.certificate_authority_id,
        cas.private_key_id,
		cas.csr_id,
        cas.status,
        cas.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        COALESCE(certs.certificate, '') AS chain
    FROM certificate_authorities cas
    LEFT JOIN certificates certs ON cas.certificate_id = certs.certificate_id

    UNION ALL

    SELECT 
        cc.certificate_authority_id,
		cc.private_key_id,
		cc.csr_id,
        cc.status,
		cc.crl,
        certs.certificate_id,
        certs.issuer_id,
        certs.certificate,
        cc.chain || CHAR(10) || certs.certificate AS chain
    FROM cas_with_chain cc
    JOIN certificates certs ON certs.certificate_id = cc.issuer_id
)
	SELECT 
		cc.certificate_authority_id as &CertificateAuthorityDenormalized.certificate_authority_id,
		cc.crl as &CertificateAuthorityDenormalized.crl,
		cc.status as &CertificateAuthorityDenormalized.status,
		pk.private_key AS &CertificateAuthorityDenormalized.private_key,
		cc.chain AS &CertificateAuthorityDenormalized.certificate_chain,
		csrs.csr AS &CertificateAuthorityDenormalized.csr
	FROM cas_with_chain cc
	LEFT JOIN private_keys pk ON cc.private_key_id = pk.private_key_id
	LEFT JOIN certificate_requests csrs ON cc.csr_id = csrs.csr_id
	WHERE cc.certificate_authority_id==$CertificateAuthorityDenormalized.certificate_authority_id
			or csrs.csr==$CertificateAuthorityDenormalized.csr
			and (issuer_id = 0 OR chain = '')
	`
)

// ListCertificateAuthorities gets every Certificate Authority entry in the table.
func (db *Database) ListCertificateAuthorities() ([]CertificateAuthority, error) {
	cas, err := ListEntities[CertificateAuthority](db, listCertificateAuthoritiesStmt)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list certificate authorities", err)
	}
	return cas, nil
}

// ListDenormalizedCertificateAuthorities gets every CertificateAuthority entry in the table
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) ListDenormalizedCertificateAuthorities() ([]CertificateAuthorityDenormalized, error) {
	cas, err := ListEntities[CertificateAuthorityDenormalized](db, listDenormalizedCertificateAuthoritiesStmt)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list denormalized certificate authorities", err)
	}
	return cas, nil
}

// GetCertificateAuthority gets a certificate authority row from the database.
func (db *Database) GetCertificateAuthority(filter CertificateAuthorityFilter) (*CertificateAuthority, error) {
	CARow, err := filter.AsCertificateAuthority()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	stmt, err := sqlair.Prepare(getCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, CARow).Get(CARow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "certificate authority")
		}
		return nil, fmt.Errorf("%w: failed to get certificate authority", ErrInternal)
	}
	return CARow, nil
}

// GetDenormalizedCertificateAuthority gets a certificate authority row from the database
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) GetDenormalizedCertificateAuthority(filter CertificateAuthorityFilter) (*CertificateAuthorityDenormalized, error) {
	CADenormalizedRow, err := filter.AsCertificateAuthorityDenormalized()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	stmt, err := sqlair.Prepare(getDenormalizedCertificateAuthorityStmt, CertificateAuthorityDenormalized{})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get denormalized certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, CADenormalizedRow).Get(CADenormalizedRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: certificate authority not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to get denormalized certificate authority", ErrInternal)
	}
	return CADenormalizedRow, nil
}

// CreateCertificateAuthority creates a new certificate authority in the database from a given CSR, private key, and certificate chain.
// The certificate chain is optional and can be empty.
func (db *Database) CreateCertificateAuthority(csrPEM string, privPEM string, crlPEM string, certChainPEM string) (int64, error) {
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
		if crlPEM == "" {
			return 0, fmt.Errorf("%w: CRL is required when adding a certificate chain to a certificate authority", ErrInvalidInput)
		}
		certID, err := db.AddCertificateChainToCertificateRequest(ByCSRID(csrID), certChainPEM)
		if err != nil {
			return 0, err
		}
		CARow = CertificateAuthority{
			CSRID:         csrID,
			CertificateID: certID,
			CRL:           crlPEM,
			PrivateKeyID:  pkID,
			Status:        CAActive,
		}
	}
	stmt, err := sqlair.Prepare(createCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return 0, fmt.Errorf("%w: failed to create certificate authority due to sql compilation error", ErrInternal)
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, CARow).Get(&outcome)
	if err != nil {
		if IsConstraintError(err, "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: certificate authority already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create certificate authority", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%w: failed to create certificate authority", ErrInternal)
	}
	return insertedRowID, nil
}

// UpdateCertificateAuthorityCertificate updates the certificate chain associated with a certificate authority.
func (db *Database) UpdateCertificateAuthorityCertificate(filter CertificateAuthorityFilter, certChainPEM string) error {
	ca, err := db.GetDenormalizedCertificateAuthority(filter)
	if err != nil {
		return err
	}
	certID, err := db.AddCertificateChainToCertificateRequest(ByCSRPEM(ca.CSRPEM), certChainPEM)
	if err != nil {
		return err
	}
	certChain, err := ParseCertificateChain(certChainPEM)
	if err != nil {
		return err
	}
	pk, err := ParsePrivateKey(ca.PrivateKeyPEM)
	if err != nil {
		return err
	}

	var newCRL string
	if ca.CRL != "" {
		existingCRL, err := ParseCRL(ca.CRL)
		if err != nil {
			return err
		}
		newCRLBytes, err := x509.CreateRevocationList(rand.Reader, existingCRL, certChain[0], pk)
		if err != nil {
			return err
		}
		newCRL = string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newCRLBytes}))
	} else {
		newCRLBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(time.Now().UnixNano()),
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().AddDate(expiryYears, 0, 0),
		}, certChain[0], pk)
		if err != nil {
			return err
		}
		newCRL = string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newCRLBytes}))
	}

	newRow := CertificateAuthority{
		CertificateAuthorityID: ca.CertificateAuthorityID,
		CertificateID:          certID,
		CRL:                    newCRL,
		Status:                 CAActive,
	}
	stmt, err := sqlair.Prepare(updateCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return fmt.Errorf("%w: failed to update certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to update certificate authority", ErrInternal)
	}
	return nil
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
		return fmt.Errorf("%w: failed to update certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, ca).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to update certificate authority", ErrInternal)
	}
	return nil
}

// UpdateCertificateAuthorityCRL updates the CRL of a certificate authority.
func (db *Database) UpdateCertificateAuthorityCRL(filter CertificateAuthorityFilter, crl string) error {
	ca, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	ca.CRL = crl
	stmt, err := sqlair.Prepare(updateCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return fmt.Errorf("%w: failed to update certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, ca).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to update certificate authority", ErrInternal)
	}
	return nil
}

// DeleteCertificateAuthority removes a certificate authority from the database.
func (db *Database) DeleteCertificateAuthority(filter CertificateAuthorityFilter) error {
	caRow, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(deleteCertificateAuthorityStmt, CertificateAuthority{})
	if err != nil {
		return fmt.Errorf("%w: failed to delete certificate authority due to sql compilation error", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, caRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete certificate authority", ErrInternal)
	}
	err = db.DeleteCertificateRequest(ByCSRID(caRow.CSRID))
	if err != nil {
		return fmt.Errorf("%w: failed to delete CA's certificate request", ErrInternal)
	}
	err = db.DeletePrivateKey(ByPrivateKeyID(caRow.PrivateKeyID))
	if err != nil {
		return fmt.Errorf("%w: failed to delete CA's private key", ErrInternal)
	}
	return nil
}

// SignCertificateRequest receives a CSR and a certificate authority.
// The CSR filter finds the CSR to sign. the CA Filter finds the CA that will issue the certificate.
func (db *Database) SignCertificateRequest(csrFilter CSRFilter, caFilter CertificateAuthorityFilter, externalHostname string) error {
	csrRow, err := db.GetCertificateRequest(csrFilter)
	if err != nil {
		return err
	}
	caRow, err := db.GetDenormalizedCertificateAuthority(caFilter)
	if err != nil {
		return err
	}
	if caRow.CertificateChain == "" {
		return errors.New("CA does not have a valid signed certificate to sign certificates")
	}
	if caRow.Status != CAActive {
		return errors.New("CA is not active to sign certificates")
	}

	block, _ := pem.Decode([]byte(csrRow.CSR))
	certRequest, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	certChain, err := ParseCertificateChain(caRow.CertificateChain)
	if err != nil {
		return err
	}
	wasSelfSigned := csrRow.CSR == caRow.CSRPEM
	block, _ = pem.Decode([]byte(caRow.PrivateKeyPEM))
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	if err = certRequest.CheckSignature(); err != nil {
		return fmt.Errorf("%w: invalid certificate request signature", err)
	}
	CSRIsForACertificateAuthority := false
	caToBeSigned, err := db.GetCertificateAuthority(ByCertificateAuthorityCSRID(csrRow.CSR_ID))
	if realError(err) {
		return err
	}
	if rowFound(err) {
		CSRIsForACertificateAuthority = true
	}
	// Create certificate template from the CSR
	certTemplate := &x509.Certificate{
		Subject:            certRequest.Subject,
		EmailAddresses:     certRequest.EmailAddresses,
		IPAddresses:        certRequest.IPAddresses,
		URIs:               certRequest.URIs,
		DNSNames:           certRequest.DNSNames,
		PublicKey:          certRequest.PublicKey,
		PublicKeyAlgorithm: certRequest.PublicKeyAlgorithm,

		// Add standard certificate fields
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(expiryYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		CRLDistributionPoints: []string{fmt.Sprintf("https://%s/api/v1/certificate_authorities/%d/crl", externalHostname, caRow.CertificateAuthorityID)},
	}

	if CSRIsForACertificateAuthority {
		certTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = true
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certChain[0], certTemplate.PublicKey, caPrivateKey)
	if err != nil {
		return err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	if CSRIsForACertificateAuthority {
		if wasSelfSigned {
			err := db.UpdateCertificateAuthorityCertificate(ByCertificateAuthorityID(caToBeSigned.CertificateAuthorityID), certPEM.String()+certPEM.String())
			if err != nil {
				return err
			}
		} else {
			err := db.UpdateCertificateAuthorityCertificate(ByCertificateAuthorityID(caToBeSigned.CertificateAuthorityID), certPEM.String()+caRow.CertificateChain)
			if err != nil {
				return err
			}
		}
	} else {
		_, err = db.AddCertificateChainToCertificateRequest(csrFilter, certPEM.String()+caRow.CertificateChain)
		if err != nil {
			return err
		}
	}
	return err
}

// RevokeCertificate revokes a certificate previously signed by a Notary CA by placing the serial number of the certificate in its issuer's CRL.
func (db *Database) RevokeCertificate(filter CSRFilter) error {
	oldRow, err := db.GetCertificateRequestAndChain(filter)
	if err != nil {
		return err
	}
	if oldRow.CertificateChain == "" {
		return fmt.Errorf("%w: no certificate to revoke with associated CSR", ErrInvalidInput)
	}
	certChain, err := SplitCertificateBundle(oldRow.CertificateChain)
	if err != nil {
		return fmt.Errorf("%w: couldn't process certificate chain", ErrInternal)
	}
	issuerCert, err := db.GetCertificate(ByCertificatePEM(certChain[1]))
	if err != nil {
		return err
	}
	certToRevoke, err := db.GetCertificate(ByCertificatePEM(certChain[0]))
	if err != nil {
		return err
	}
	ca, err := db.GetCertificateAuthority(ByCertificateAuthorityCertificateID(issuerCert.CertificateID))
	if !rowFound(err) {
		return fmt.Errorf("%w: certificates need to be signed by a notary managed certificate authority in order to be revoked", ErrInvalidInput)
	}
	if realError(err) {
		return fmt.Errorf("%w: couldn't get certificate authority of issuer", ErrInternal)
	}
	caWithPK, err := db.GetDenormalizedCertificateAuthority(ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		return err
	}
	newCRL, err := AddCertificateToCRL(oldRow.CertificateChain, caWithPK.PrivateKeyPEM, ca.CRL)
	if err != nil {
		return fmt.Errorf("%w: couldn't add certificate to certificate authority", ErrInternal)
	}
	err = db.DeleteCertificate(ByCertificateID(certToRevoke.CertificateID))
	if err != nil {
		return err
	}
	err = db.UpdateCertificateAuthorityCRL(ByCertificateAuthorityID(ca.CertificateAuthorityID), newCRL)
	if err != nil {
		return err
	}

	// Check if the certificate being revoked belongs to a CA, if so, set its status to pending
	revokedCA, err := db.GetCertificateAuthority(ByCertificateAuthorityCertificateID(certToRevoke.CertificateID))
	if rowFound(err) {
		err = db.UpdateCertificateAuthorityStatus(ByCertificateAuthorityID(revokedCA.CertificateAuthorityID), CAPending)
		if err != nil {
			return err
		}
	} else if realError(err) {
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
		Status:        "Revoked",
	}

	err = db.conn.Query(context.Background(), stmt, newRow).Run()
	return err
}

func rowFound(err error) bool {
	return err == nil
}

func realError(err error) bool {
	return err != nil && !errors.Is(err, sqlair.ErrNoRows) && !errors.Is(err, ErrNotFound)
}
