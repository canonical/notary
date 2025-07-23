package db

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// ListCertificateAuthorities gets every Certificate Authority entry in the table.
func (db *Database) ListCertificateAuthorities() ([]CertificateAuthority, error) {
	return ListEntities[CertificateAuthority](db, db.stmts.ListCertificateAuthorities)
}

// ListDenormalizedCertificateAuthorities gets every CertificateAuthority entry in the table
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) ListDenormalizedCertificateAuthorities() ([]CertificateAuthorityDenormalized, error) {
	return ListEntities[CertificateAuthorityDenormalized](db, db.stmts.ListDenormalizedCertificateAuthorities)
}

// GetCertificateAuthority gets a certificate authority row from the database.
func (db *Database) GetCertificateAuthority(filter CertificateAuthorityFilter) (*CertificateAuthority, error) {
	caRow := filter.AsCertificateAuthority()
	return GetOneEntity[CertificateAuthority](db, db.stmts.GetCertificateAuthority, *caRow)
}

// GetDenormalizedCertificateAuthority gets a certificate authority row from the database
// but instead of returning ID's that reference other table rows, it embeds the row data directly into the response object.
func (db *Database) GetDenormalizedCertificateAuthority(filter CertificateAuthorityDenormalizedFilter) (*CertificateAuthorityDenormalized, error) {
	CARow := filter.AsCertificateAuthorityDenormalized()
	return GetOneEntity[CertificateAuthorityDenormalized](db, db.stmts.GetDenormalizedCertificateAuthority, *CARow)
}

// CreateCertificateAuthority creates a new certificate authority in the database from a given CSR, private key, and certificate chain.
// The certificate chain is optional and can be empty.
func (db *Database) CreateCertificateAuthority(csrPEM string, privPEM string, crlPEM string, certChainPEM string, userID int64) (int64, error) {
	csrID, err := db.CreateCertificateRequest(csrPEM, userID)
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
		Enabled:      false,
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
			Enabled:       true,
		}
	}
	insertedRowID, err := CreateEntity(db, db.stmts.CreateCertificateAuthority, CARow)
	if err != nil {
		return 0, err
	}
	return insertedRowID, nil
}

// UpdateCertificateAuthorityCertificate updates the certificate chain associated with a certificate authority.
func (db *Database) UpdateCertificateAuthorityCertificate(filter CertificateAuthorityDenormalizedFilter, certChainPEM string) error {
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
	pkObject, err := db.GetDecryptedPrivateKey(ByPrivateKeyID(ca.PrivateKeyID))
	if err != nil {
		return err
	}
	pk, err := ParsePrivateKey(pkObject.PrivateKeyPEM)
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
			NextUpdate: time.Now().AddDate(CAMaxExpiryYears, 0, 0),
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
		Enabled:                true,
	}
	return UpdateEntity(db, db.stmts.UpdateCertificateAuthority, newRow)
}

// UpdateCertificateAuthorityStatus updates the status of a certificate authority.
func (db *Database) UpdateCertificateAuthorityEnabledStatus(filter CertificateAuthorityFilter, enabled bool) error {
	ca, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	ca.Enabled = enabled
	return UpdateEntity(db, db.stmts.UpdateCertificateAuthority, ca)
}

// UpdateCertificateAuthorityCRL updates the CRL of a certificate authority.
func (db *Database) UpdateCertificateAuthorityCRL(filter CertificateAuthorityFilter, crl string) error {
	ca, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	ca.CRL = crl
	return UpdateEntity(db, db.stmts.UpdateCertificateAuthority, ca)
}

// DeleteCertificateAuthority removes a certificate authority from the database.
func (db *Database) DeleteCertificateAuthority(filter CertificateAuthorityFilter) error {
	caRow, err := db.GetCertificateAuthority(filter)
	if err != nil {
		return err
	}
	err = DeleteEntity(db, db.stmts.DeleteCertificateAuthority, caRow)
	if err != nil {
		return err
	}
	err = db.DeleteCertificateRequest(ByCSRID(caRow.CSRID))
	if err != nil {
		return err
	}
	return db.DeletePrivateKey(ByPrivateKeyID(caRow.PrivateKeyID))
}
