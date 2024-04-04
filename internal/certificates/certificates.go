package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// GenerateCACertificate generates a one time discardable root CA for the running GoCert webserver
func GenerateCACertificate() (x509.Certificate, rsa.PrivateKey, error) {
	caCertTemplate := &x509.Certificate{}
	caCertPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	caCert, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caCertPK.PublicKey, caCertPK)
	return caCert, *caCertPK, nil
}

// GenerateSelfSignedCertificate will create a certificate and pk for GoCert coming from a rootCA
// This certificate and PK is not saved anywhere.
// This certificate and PK should either be saved somewhere, or a real certificate should be provided to GoCert
func GenerateSelfSignedCertificate() ([]byte, []byte, error) {
	// rsa.GenerateKey()
	// x509.CreateCertificate()
}
