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

	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 1, got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 2 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 2, got %d", csrID)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), AppleCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), BananaCert+IntermediateCert+RootCert)
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
	if certs[0].IssuerID != 0 || certs[1].IssuerID != 1 || certs[2].IssuerID != 2 || certs[3].IssuerID != 2 {
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

	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), BananaCert+IntermediateCert+RootCert)
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
	chain, err := database.GetCertificateChain(db.ByCertificatePEM(AppleCert))
	if err != nil {
		t.Fatalf("Couldn't get certificate chain: %s", err)
	}
	if len(chain) != 3 {
		t.Fatalf("Expected 3 certificates in the chain, got %d", len(chain))
	}
	if chain[0].CertificatePEM != AppleCert ||
		chain[1].CertificatePEM != IntermediateCert ||
		chain[2].CertificatePEM != RootCert {
		t.Fatalf("Certificate chain order or content incorrect")
	}

	err = database.DeleteCertificate(db.ByCertificatePEM(AppleCert))
	if err != nil {
		t.Fatalf("Couldn't delete certificate: %s", err)
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(AppleCert))
	if err == nil {
		t.Fatalf("Expected error when retrieving deleted certificate, got nil")
	}

	certs, err = database.ListCertificates()
	if err != nil {
		t.Fatalf("Couldn't complete List: %s", err)
	}
	if len(certs) != 3 {
		t.Fatalf("Expected 3 Certificates, only got %d", len(certs))
	}
	err = database.DeleteCertificate(db.ByCertificatePEM("Nonexistent cert"))
	if err != nil {
		t.Fatalf("Attempting to delete a nonexistent certificate should not return an error")
	}
	certs, err = database.ListCertificates()
	if err != nil {
		t.Fatalf("Couldn't complete List: %s", err)
	}
	if len(certs) != 3 {
		t.Fatalf("Expected 3 Certificates, only got %d", len(certs))
	}
}

func TestGetCertificateFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	database.CreateCertificateRequest(AppleCSR)                                                                                      //nolint:errcheck
	database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), AppleCert+IntermediateCert+"some extra string"+RootCert) //nolint:errcheck

	cert, err := database.GetCertificate(db.ByCertificatePEM(AppleCert))
	if err != nil || cert.CertificatePEM != AppleCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, AppleCert)
	}

	cert, err = database.GetCertificate(db.ByCertificateID(2))
	if err != nil || cert.CertificatePEM != AppleCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, AppleCert)
	}

	_, err = database.GetCertificate(db.ByCertificatePEM("nonexistent cert"))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a nonexistent certificate.")
	}

	_, err = database.GetCertificate(db.ByCertificatePEM(""))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a certificate with an empty PEM string.")
	}

	_, err = database.GetCertificate(db.ByCertificateID(5))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a certificate with an invalid ID.")
	}
	_, err = database.GetCertificate(db.ByCertificateID(0))
	if err == nil {
		t.Fatalf("An error should be returned.")
	}
}

func TestCertificateAddFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	_, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	InvalidCert := strings.ReplaceAll(BananaCert, "/", "+")
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), InvalidCert); err == nil {
		t.Fatalf("Expected adding certificate chain with invalid cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), BananaCert); err == nil {
		t.Fatalf("Expected adding certificate chain with mismatched cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), ""); err == nil {
		t.Fatalf("Expected adding certificate chain with empty string to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), "random string"); err == nil {
		t.Fatalf("Expected adding certificate chain with random string to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(1), InvalidCert); err == nil {
		t.Fatalf("Expected adding certificate chain with invalid cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), BananaCert); err == nil {
		t.Fatalf("Expected adding certificate chain with mismatched cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), ""); err == nil {
		t.Fatalf("Expected adding certificate chain with empty string to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), "random string"); err == nil {
		t.Fatalf("Expected adding certificate chain with random string to fail")
	}
}

func TestGetCertificateChainFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	_, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(AppleCSR), AppleCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(AppleCert))
	if err != nil {
		t.Fatalf("An error should not be returned when retrieving a certificate chain.")
	}
	_, err = database.GetCertificateChain(db.ByCertificateID(1))
	if err != nil {
		t.Fatalf("An error should not be returned when retrieving a certificate chain.")
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM("nonexistent cert"))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a nonexistent certificate chain.")
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(""))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a certificate chain with an empty PEM string.")
	}
	_, err = database.GetCertificateChain(db.ByCertificateID(5))
	if err == nil {
		t.Fatalf("An error should be returned when retrieving a certificate chain with an invalid ID.")
	}
}
