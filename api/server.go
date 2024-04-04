// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/canonical/gocert/internal/certificates"
)

// decodeCertificateAndPK takes in two PEM strings and decodes them into bytes
func decodeCertificateAndPK(certificate, key string) ([]byte, []byte, error) {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return nil, nil, errors.New("PEM Certificate string not found or malformed")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("given PEM string not a certificate")
	}
	certBytes := block.Bytes

	block, _ = pem.Decode([]byte(key))
	if block == nil {
		return nil, nil, errors.New("PEM Private Key string not found or malformed")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, nil, errors.New("given PEM string not a private key")
	}
	pkBytes := block.Bytes
	return certBytes, pkBytes, nil
}

// formatServerCertificates takes in a certificate and a private key and converts it into a
// format usable by net/http
func formatServerCertificates(certificate, key string) (tls.Certificate, error) {
	var serverCerts tls.Certificate
	var serverCert []byte
	var serverPK []byte
	var err error
	if certificate != "" && key != "" {
		serverCert, serverPK, err = decodeCertificateAndPK(certificate, key)
		if err != nil {
			return serverCerts, err
		}
	} else {
		caCert, caPK, err := certificates.GenerateCACertificate()
		if err != nil {
			return serverCerts, err
		}
		serverCert, serverPK, err = certificates.GenerateSelfSignedCertificate(caCert, caPK)
		if err != nil {
			return serverCerts, err
		}
	}
	serverCerts, err = tls.X509KeyPair(serverCert, serverPK)
	if err != nil {
		return serverCerts, err
	}
	return serverCerts, nil
}

// NewServer creates a new http server with handlers that Go can start listening to
func NewServer(version int, certificate, key string) (*http.Server, error) {
	serverCerts, err := formatServerCertificates(certificate, key)
	if err != nil {
		return nil, err
	}
	s := &http.Server{
		Addr: ":8080",

		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCerts},
		},
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world"))
	})
	return s, nil
}
