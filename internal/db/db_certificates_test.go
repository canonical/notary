package db_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCertificatesEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 1, got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.BananaCSR, userEmail)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 2 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 2, got %d", csrID)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCert+tu.IntermediateCert+tu.RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCert+tu.IntermediateCert+tu.RootCert)
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

	retrievedCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != tu.AppleCSR {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}
	if retrievedCSR.CertificateID != 3 {
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	retrievedCSRWithCert, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSRWithCert.CertificateChain != tu.AppleCert+"\n"+tu.IntermediateCert+"\n"+tu.RootCert {
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCert+tu.IntermediateCert+tu.RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSRWithCert, _ = database.GetCertificateRequestAndChain(db.ByCSRPEM(tu.BananaCSR))
	if retrievedCSRWithCert.CertificateChain != tu.BananaCert+"\n"+tu.IntermediateCert+"\n"+tu.RootCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSRWithCert.CertificateChain, tu.BananaCert+tu.IntermediateCert+tu.RootCert)
	}
	err = database.RevokeCertificate(db.ByCSRPEM(tu.BananaCSR))
	if !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("Should have failed to revoke CSR that was signed outside of notary.")
	}
	chain, err := database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCert))
	if err != nil {
		t.Fatalf("Couldn't get certificate chain: %s", err)
	}
	if len(chain) != 3 {
		t.Fatalf("Expected 3 certificates in the chain, got %d", len(chain))
	}
	if chain[0].CertificatePEM != tu.AppleCert ||
		chain[1].CertificatePEM != tu.IntermediateCert ||
		chain[2].CertificatePEM != tu.RootCert {
		t.Fatalf("Certificate chain order or content incorrect")
	}

	err = database.DeleteCertificate(db.ByCertificatePEM(tu.AppleCert))
	if err != nil {
		t.Fatalf("Couldn't delete certificate: %s", err)
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCert))
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
	if err == nil {
		t.Fatalf("Attempting to delete a nonexistent certificate should return an error")
	}
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected a not found error when deleting a nonexistent certificate, got %s", err)
	}
	certs, err = database.ListCertificates()
	if err != nil {
		t.Fatalf("Couldn't complete List: %s", err)
	}
	if len(certs) != 3 {
		t.Fatalf("Expected 3 Certificates, only got %d", len(certs))
	}
}

func TestCertificateRequestUserMappingEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	userID, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	if userID == 0 {
		t.Fatalf("CreateUser should return a valid user ID, got 0")
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 1, got %d", csrID)
	}

	retrievedCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.UserEmail != userEmail {
		t.Fatalf("The CSR from the database doesn't match the user that was given")
	}

	err = database.DeleteUser(db.ByUserID(userID))
	if err != nil {
		t.Fatalf("Couldn't complete DeleteUser: %s", err)
	}

	retrievedCSR, err = database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.UserEmail != userEmail {
		t.Fatalf("The User ID from the database should be set to 0 after deleting the user, got %s", retrievedCSR.UserEmail)
	}
}

func TestGetCertificateFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	database.CreateCertificateRequest(tu.AppleCSR, userEmail)                                                                                    //nolint:errcheck
	database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCert+tu.IntermediateCert+"some extra string"+tu.RootCert) //nolint:errcheck

	cert, err := database.GetCertificate(db.ByCertificatePEM(tu.AppleCert))
	if err != nil || cert.CertificatePEM != tu.AppleCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, tu.AppleCert)
	}

	cert, err = database.GetCertificate(db.ByCertificateID(2))
	if err != nil || cert.CertificatePEM != tu.AppleCert {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, tu.AppleCert)
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
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(tu.BananaCSR, userEmail)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	InvalidCert := strings.ReplaceAll(tu.BananaCert, "/", "+")
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), InvalidCert); err == nil {
		t.Fatalf("Expected adding certificate chain with invalid cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.BananaCert); err == nil {
		t.Fatalf("Expected adding certificate chain with mismatched cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), ""); err == nil {
		t.Fatalf("Expected adding certificate chain with empty string to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), "random string"); err == nil {
		t.Fatalf("Expected adding certificate chain with random string to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(1), InvalidCert); err == nil {
		t.Fatalf("Expected adding certificate chain with invalid cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), tu.BananaCert); err == nil {
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
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(tu.BananaCSR, userEmail)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCert+tu.IntermediateCert+tu.RootCert)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCert))
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
