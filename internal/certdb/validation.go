package certdb

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ValidateCertificateRequest validates the given CSR string to the following:
// The string must be a valid PEM string, and should be of type CERTIFICATE REQUEST
// The PEM string should be able to be parsed into a x509 Certificate Request
func ValidateCertificateRequest(csrString string) error {
	block, _ := pem.Decode([]byte(csrString))
	if block == nil {
		return errors.New("PEM Certificate Request string not found or malformed")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return errors.New("given PEM string not a certificate request")
	}
	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// ValidateCertificate validates the given Cert string to the following:
// The given CSR must pass the validation provided by ValidateCertificateRequest
// The cert string must be a valid PEM string, and should be of type CERTIFICATE
// The PEM string should be able to be parsed into a x509 Certificate
// The given cert and CSR must share the same public key
func ValidateCertificate(certString string, csrString string) error {
	if err := ValidateCertificateRequest(csrString); err != nil {
		return err
	}
	csrBlock, _ := pem.Decode([]byte(csrString))
	csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
	certBlock, _ := pem.Decode([]byte(certString))
	if certBlock == nil {
		return errors.New("PEM Certificate string not found or malformed")
	}
	if certBlock.Type != "CERTIFICATE" {
		return errors.New("given PEM string not a certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	certKey := cert.PublicKey.(*rsa.PublicKey)
	csrKey := csr.PublicKey.(*rsa.PublicKey)
	if !csrKey.Equal(certKey) {
		return errors.New("certificate does not match CSR")
	}
	return nil
}
