// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/canonical/gocert/internal/certificates"
)

// loadServerCertificates takes in a certificate and a private key and determines
// whether to use self signed or given certificates, then returns it in a format
// expected by the server
func loadServerCertificates(certificate, key string) (*tls.Certificate, error) {
	if certificate == "" || key == "" {
		caCertPEM, caPrivateKeyPEM, err := certificates.GenerateCACertificate()
		if err != nil {
			return nil, err
		}
		certificate, key, err = certificates.GenerateSelfSignedCertificate(caCertPEM, caPrivateKeyPEM)
		if err != nil {
			return nil, err
		}
	}
	serverCerts, err := tls.X509KeyPair([]byte(certificate), []byte(key))
	if err != nil {
		return nil, err
	}
	return &serverCerts, nil
}

// NewServer creates a new http server with handlers that Go can start listening to
func NewServer(version int, certificate, key string) (*http.Server, error) {
	serverCerts, err := loadServerCertificates(certificate, key)
	if err != nil {
		return nil, err
	}
	s := &http.Server{
		Addr: ":8080",

		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*serverCerts},
		},
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world"))
	})
	return s, nil
}
