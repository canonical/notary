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
func ValidateCertificateRequest(csr string) error {
	block, _ := pem.Decode([]byte(csr))
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
// The cert string must be a valid PEM string, and should be of type CERTIFICATE
// The PEM string should be able to be parsed into a x509 Certificate
func ValidateCertificate(cert string) error {
	certBlock, _ := pem.Decode([]byte(cert))
	if certBlock == nil {
		return errors.New("PEM Certificate string not found or malformed")
	}
	if certBlock.Type != "CERTIFICATE" {
		return errors.New("given PEM string not a certificate")
	}
	_, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// CertificateMatchesCSR makes sure that the given certificate and CSR match.
// The given CSR and Cert must pass their respective validation functions
// The given cert and CSR must share the same public key
func CertificateMatchesCSR(cert string, csr string) error {
	if err := ValidateCertificateRequest(csr); err != nil {
		return err
	}
	if err := ValidateCertificate(cert); err != nil {
		return err
	}
	csrBlock, _ := pem.Decode([]byte(csr))
	parsedCSR, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
	certBlock, _ := pem.Decode([]byte(cert))
	parsedCERT, _ := x509.ParseCertificate(certBlock.Bytes)
	certKey := parsedCERT.PublicKey.(*rsa.PublicKey)
	csrKey := parsedCSR.PublicKey.(*rsa.PublicKey)
	if !csrKey.Equal(certKey) {
		return errors.New("certificate does not match CSR")
	}
	return nil
}
