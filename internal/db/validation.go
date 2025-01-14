package db

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
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
	// TODO: We should validate the actual certificate request parameters here too. (Has the required fields etc)
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
			return errors.New("a given PEM string was not a certificate")
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}
		certificates = append(certificates, certificate)
		certData = rest
	}

	if len(certificates) < 2 {
		return errors.New("less than 2 certificate PEM strings were found")
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
			return fmt.Errorf("invalid certificate chain: certificate %d, certificate %d: keys do not match: %s", i, i+1, err.Error())
		}
	}
	// TODO: We should validate the actual certificate parameters here too. (Has the required fields etc)
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

// SanitizeCertificateBundle takes in a valid certificate string and formats it
// The final list has pure certificate PEM strings with no trailing or leading whitespace
func sanitizeCertificateBundle(cert string) ([]string, error) {
	var buff bytes.Buffer
	var output []string
	certData := []byte(cert)
	for {
		certBlock, rest := pem.Decode(certData)
		if certBlock == nil {
			break
		}
		err := pem.Encode(&buff, certBlock)
		if err != nil {
			return nil, err
		}
		output = append(output, buff.String())
		buff.Reset()
		certData = rest
	}
	return output, nil
}

// Takes the password string, makes sure it's not empty, and hashes it using bcrypt
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
