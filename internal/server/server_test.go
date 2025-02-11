package server_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/server"
)

func TestNewSuccess(t *testing.T) {
	certPath := filepath.Join("testdata", "cert.pem")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	keyPath := filepath.Join("testdata", "key.pem")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	s, err := server.New(8000, []byte(cert), []byte(key), "certs.db", false)
	if err != nil {
		t.Errorf("Error occurred: %s", err)
	}
	if s.TLSConfig.Certificates == nil {
		t.Errorf("No certificates were configured for server")
	}
}

func TestInvalidKeyFailure(t *testing.T) {
	certPath := filepath.Join("testdata", "cert.pem")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	_, err = server.New(8000, []byte(cert), []byte{}, "certs.db", false)
	if err == nil {
		t.Errorf("No error was thrown for invalid key")
	}
}
