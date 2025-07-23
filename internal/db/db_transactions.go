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

// RevokeCertificate revokes a certificate previously signed by a Notary CA by placing the serial number of the certificate in its issuer's CRL.
func (db *Database) RevokeCertificate(filter *CSRFilter) error {
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
		Status:        CSRStatusRevoked,
	}

	err = UpdateEntity(db, db.stmts.UpdateCertificateRequest, newRow)
	return err
}

// SignCertificateRequest receives a CSR and a certificate authority.
// The CSR filter finds the CSR to sign. the CA Filter finds the CA that will issue the certificate.
func (db *Database) SignCertificateRequest(csrFilter *CSRFilter, caFilter CertificateAuthorityDenormalizedFilter, externalHostname string) error {
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
