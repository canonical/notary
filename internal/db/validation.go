package db

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ValidateCertificateRequest validates the given CSR string to the following:
// The string must be a valid PEM string, and should be of type CERTIFICATE REQUEST
// The PEM string should be able to be parsed into a x509 Certificate Request
func ValidateCertificateRequest(csr string) error {
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		return fmt.Errorf("%w: PEM Certificate Request string not found or malformed", ErrInvalidCertificateRequest)
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("%w: given PEM string not a certificate request", ErrInvalidCertificateRequest)
	}
	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCertificateRequest, err)
	}
	return nil
}

// ValidateCertificate validates the given Cert string to the following:
//
// The string must include 2 or more PEM formatted certificate strings.
// Each cert must be a valid PEM string, and should be capable of being parsed into type x509 CERTIFICATE
// Each subsequent certificate in the string should be the issuer of the previous string, which means:
//
// All except the first certificate should have the "is a CA" Basic Constraint.
// The public key of the certificate should match the public key of the following certificate.
// The issuer field of the certificate should match the subject field of the following certificate.
func ValidateCertificate(cert string) error {
	certData := []byte(cert)
	certificates := []*x509.Certificate{}

	for {
		certBlock, rest := pem.Decode(certData)
		if certBlock == nil {
			break
		}
		if certBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("%w: a given PEM string was not a certificate", ErrInvalidCertificate)
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidCertificate, err)
		}
		certificates = append(certificates, certificate)
		certData = rest
	}

	if len(certificates) < 2 {
		return fmt.Errorf("%w: less than 2 certificate PEM strings were found", ErrInvalidCertificate)
	}

	for i, firstCert := range certificates[:len(certificates)-1] {
		secondCert := certificates[i+1]
		if !secondCert.IsCA {
			return fmt.Errorf("invalid certificate chain: certificate %d is not a certificate authority", i+1)
		}
		if !bytes.Equal(firstCert.RawIssuer, secondCert.RawSubject) {
			return fmt.Errorf("invalid certificate chain: certificate %d, certificate %d: subjects do not match", i, i+1)
		}
		if err := firstCert.CheckSignatureFrom(secondCert); err != nil {
			return fmt.Errorf("invalid certificate chain: certificate %d, certificate %d: keys do not match: %w", i, i+1, err)
		}
	}
	return nil
}

// CertificateMatchesCSR makes sure that the given certificate and CSR match.
// The given CSR and Cert must pass their respective validation functions
// The given CSR and Cert must share the same public key
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

func ValidatePrivateKey(pk string) error {
	block, _ := pem.Decode([]byte(pk))
	if block == nil {
		return fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPrivateKey)
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return fmt.Errorf("%w: invalid PEM block type: %s", ErrInvalidPrivateKey, block.Type)
	}

	var err error
	if block.Type == "RSA PRIVATE KEY" {
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return fmt.Errorf("%w: failed to parse private key: %v", ErrInvalidPrivateKey, err)
	}
	return nil
}

func ValidateUser(username string, roleID RoleID) error {
	if username == "" {
		return fmt.Errorf("%w: invalid username or password", ErrInvalidUser)
	}
	if roleID < 0 || roleID > 3 {
		return fmt.Errorf("%w: invalid role ID: %d", ErrInvalidUser, roleID)
	}
	return nil
}
