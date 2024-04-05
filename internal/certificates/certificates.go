package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

// GenerateCACertificate generates a one time discardable root CA for the running GoCert webserver
func GenerateCACertificate() (string, string, error) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Canonical, INC."},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return "", "", err
	}

	caCertPEM := new(bytes.Buffer)
	err = pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return "", "", err
	}

	caPrivateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})
	if err != nil {
		return "", "", err
	}
	return caCertPEM.String(), caPrivateKeyPEM.String(), nil
}

// GenerateSelfSignedCertificate will create a certificate and pk for GoCert coming from a rootCA
// This certificate and PK is not saved anywhere.
// This certificate and PK should either be saved somewhere, or a real certificate should be provided to GoCert
func GenerateSelfSignedCertificate(caCertPEM, caPrivateKeyPEM string) (string, string, error) {
	caCert, err := ParseCertificate(caCertPEM)
	if err != nil {
		return "", "", nil
	}
	caPrivateKey, err := ParsePKCS1PrivateKey(caPrivateKeyPEM)
	if err != nil {
		return "", "", nil
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Canonical, INC."},
			Country:      []string{"US"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, // TODO
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, &caCert, &certPrivateKey.PublicKey, &caPrivateKey)
	if err != nil {
		return "", "", err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return "", "", err
	}
	certPrivateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})
	if err != nil {
		return "", "", err
	}
	return certPEM.String(), certPrivateKeyPEM.String(), nil
}

// ParseCertificate parses a PEM string into a native x509.Certificate object
func ParseCertificate(certPEM string) (x509.Certificate, error) {
	cert := &x509.Certificate{}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return *cert, errors.New("PEM Certificate string not found or malformed")
	}
	if block.Type != "CERTIFICATE" {
		return *cert, errors.New("given PEM string not a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return *cert, err
	}
	return *cert, nil
}

// ParsePrivateKey parses a PEM private key string into a native rsa.PrivateKey object
func ParsePKCS1PrivateKey(pkPEM string) (rsa.PrivateKey, error) {
	pk := &rsa.PrivateKey{}
	block, _ := pem.Decode([]byte(pkPEM))
	if block == nil {
		return *pk, errors.New("PEM private key string not found or malformed")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return *pk, errors.New("given PEM string not an rsa private key")
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return *pk, err
	}
	return *pk, nil
}
