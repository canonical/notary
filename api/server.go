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

// formatServerCertificates takes in a certificate and a private key and converts it into a
// format usable by net/http
func formatServerCertificates(certificate, key string) (tls.Certificate, error) {
	var serverCerts tls.Certificate
	var serverCert []byte
	var serverPK []byte
	var err error
	if certificate != "" && key != "" {
		block, _ := pem.Decode([]byte(certificate))
		if block == nil {
			return serverCerts, errors.New("PEM Certificate string not found or malformed")
		}
		if block.Type != "CERTIFICATE" {
			return serverCerts, errors.New("given PEM string not a certificate")
		}
		serverCert = block.Bytes
		block, _ = pem.Decode([]byte(key))
		if block == nil {
			return serverCerts, errors.New("PEM Private Key string not found or malformed")
		}
		if block.Type != "PRIVATE KEY" {
			return serverCerts, errors.New("given PEM string not a private key")
		}
		serverPK = block.Bytes
	} else {
		serverCert, serverPK, err = certificates.GenerateSelfSignedCertificate()
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
