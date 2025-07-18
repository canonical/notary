package db

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// SignCertificateRequest receives a CSR and a certificate authority.
// The CSR filter finds the CSR to sign. the CA Filter finds the CA that will issue the certificate.
func (db *Database) SignCertificateRequest(csrFilter CSRFilter, caFilter CertificateAuthorityDenormalizedFilter, externalHostname string) error {
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
	if !caRow.Enabled {
		return errors.New("CA is not enabled to sign certificates")
	}

	expiryDate := certificateExpiryDate(caRow.CertificateChain)
	if expiryDate.Before(time.Now()) {
		return errors.New("CA certificate is expired")
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
	privateKeyObject, err := db.GetDecryptedPrivateKey(ByPrivateKeyID(caRow.PrivateKeyID))
	if err != nil {
		return err
	}
	block, _ = pem.Decode([]byte(privateKeyObject.PrivateKeyPEM))
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
		NotAfter:     time.Now().AddDate(CAMaxExpiryYears, 0, 0),
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
			err := db.UpdateCertificateAuthorityCertificate(ByCertificateAuthorityDenormalizedID(caToBeSigned.CertificateAuthorityID), certPEM.String()+certPEM.String())
			if err != nil {
				return err
			}
		} else {
			err := db.UpdateCertificateAuthorityCertificate(ByCertificateAuthorityDenormalizedID(caToBeSigned.CertificateAuthorityID), certPEM.String()+caRow.CertificateChain)
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
	caWithPK, err := db.GetDenormalizedCertificateAuthority(ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		return err
	}
	pk, err := db.GetDecryptedPrivateKey(ByPrivateKeyID(caWithPK.PrivateKeyID))
	if err != nil {
		return err
	}
	newCRL, err := AddCertificateToCRL(oldRow.CertificateChain, pk.PrivateKeyPEM, ca.CRL)
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
		err = db.UpdateCertificateAuthorityEnabledStatus(ByCertificateAuthorityID(revokedCA.CertificateAuthorityID), false)
		if err != nil {
			return err
		}
	} else if realError(err) {
		return err
	}

	newRow := CertificateRequest{
		CSR_ID:        oldRow.CSR_ID,
		CSR:           oldRow.CSR,
		CertificateID: 0,
		Status:        "Revoked",
	}

	err = UpdateEntity(db, db.stmts.UpdateCertificateRequest, newRow)
	return err
}

func certificateExpiryDate(certString string) time.Time {
	certBlock, _ := pem.Decode([]byte(certString))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	return cert.NotAfter
}
