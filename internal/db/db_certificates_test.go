package db_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestCertificatesEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	err = database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = database.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), AppleCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), BananaCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	certs, err := database.ListCertificates()
	if err != nil {
		t.Fatalf("Couldn't complete List: %s", err)
	}
	if len(certs) != 4 {
		t.Fatalf("Expected 4 Certificates, only got %d", len(certs))
	}
	if certs[0].Issuer != 0 || certs[1].Issuer != 1 || certs[2].Issuer != 2 || certs[3].Issuer != 2 {
		t.Fatalf("Certificate chains were not created correctly")
	}

	retrievedCSR, err := database.GetCertificateRequest(db.ByCSRPEM(AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != AppleCSR {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}
	if retrievedCSR.CertificateID != 3 {
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	retrievedCSRWithCert, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSRWithCert.CertificateChain != AppleCert+"\n"+IntermediateCert+"\n"+RootCert {
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), BananaCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSRWithCert, _ = database.GetCertificateRequestAndChain(db.ByCSRPEM(BananaCSR))
	if retrievedCSRWithCert.CertificateChain != BananaCert+"\n"+IntermediateCert+"\n"+RootCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSRWithCert.CertificateChain, BananaCert+IntermediateCert+RootCert)
	}
	err = database.RevokeCertificate(db.ByCSRPEM(BananaCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Update to revoke certificate: %s", err)
	}
	retrievedCSR, _ = database.GetCertificateRequest(db.ByCSRPEM(BananaCSR))
	if retrievedCSR.Status != "Revoked" {
		t.Fatalf("Couldn't revoke certificate")
	}
}

func TestCreateCertificateFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	database.CreateCertificateRequest(AppleCSR)  //nolint:errcheck
	database.CreateCertificateRequest(BananaCSR) //nolint:errcheck
	err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), AppleCert+IntermediateCert+"some extra string"+RootCert)
	if err != nil {
		t.Fatalf("The certificate should have uploaded successfully")
	}

	cert, err := database.GetCertificate(db.ByCertificatePEM(AppleCert))
	if err != nil || cert.CertificatePEM != AppleCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, AppleCert)
	}

	_, err = database.GetCertificate(db.ByCertificatePEM("nonexistent cert"))
	if err == nil {
		t.Fatalf("An error should be returned.")
	}
	_, err = database.GetCertificate(db.ByCertificatePEM(""))
	if err == nil {
		t.Fatalf("An error should be returned.")
	}
	_, err = database.GetCertificate(db.ByCertificateID(5))
	if err == nil {
		t.Fatalf("An error should be returned.")
	}
	_, err = database.GetCertificate(db.ByCertificateID(0))
	if err == nil {
		t.Fatalf("An error should be returned.")
	}
}

func TestCertificateAddFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	database.CreateCertificateRequest(AppleCSR)  //nolint:errcheck
	database.CreateCertificateRequest(BananaCSR) //nolint:errcheck
	InvalidCert := strings.ReplaceAll(BananaCert, "/", "+")
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), InvalidCert); err == nil {
		t.Fatalf("Expected updating with invalid cert to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), BananaCert); err == nil {
		t.Fatalf("Expected updating with mismatched cert to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), ""); err == nil {
		t.Fatalf("Expected updating with empty string to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), "random string"); err == nil {
		t.Fatalf("Expected updating with random string to fail")
	}

	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(1), InvalidCert); err == nil {
		t.Fatalf("Expected updating with invalid cert to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), BananaCert); err == nil {
		t.Fatalf("Expected updating with mismatched cert to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), ""); err == nil {
		t.Fatalf("Expected updating with empty string to fail")
	}
	if err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), "random string"); err == nil {
		t.Fatalf("Expected updating with random string to fail")
	}
}
