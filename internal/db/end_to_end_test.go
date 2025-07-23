package db_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption"
	"github.com/canonical/notary/internal/hashing"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCSRsEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.BananaCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	if csrID != 2 {
		t.Fatalf("Couldn't complete Create: expected user id 2, but got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.StrawberryCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	if csrID != 3 {
		t.Fatalf("Couldn't complete Create: expected user id 3, but got %d", csrID)
	}
	res, err := database.ListCertificateRequests()
	if err != nil {
		t.Fatalf("Couldn't list all CSRs: %s", err)
	}
	if len(res) != 3 {
		t.Fatalf("One or more CSRs weren't found in DB")
	}
	csrs := make(map[string]bool)
	for _, csr := range res {
		csrs[csr.CSR] = true
	}
	if !csrs[tu.AppleCSR] || !csrs[tu.BananaCSR] || !csrs[tu.StrawberryCSR] {
		t.Fatalf("One or more CSRs weren't found in DB")
	}
	appleCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	if appleCSR.CSR != tu.AppleCSR {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}
	if err = database.DeleteCertificateRequest(db.ByCSRPEM(tu.AppleCSR)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = database.ListCertificateRequests()
	if len(res) != 2 {
		t.Fatalf("CSR's weren't deleted from the DB properly")
	}
	for _, csr := range res {
		if csr.CSR == tu.AppleCSR {
			t.Fatalf("CSR was not deleted from the DB")
		}
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't add certificate chain to CSR: %s", err)
	}
	bananaCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.BananaCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	if bananaCSR.CertificateID != 3 {
		t.Fatalf("Certificate chain was not added to CSR")
	}

	csrsWithChain, err := database.ListCertificateRequestsWithCertificates()
	if err != nil {
		t.Fatalf("Couldn't list all CSRs with chains: %s", err)
	}
	if len(csrsWithChain) != 2 {
		t.Fatalf("One or more CSRs with chains weren't found in DB")
	}
	if csrsWithChain[0].CertificateChain == "" && csrsWithChain[1].CertificateChain == "" {
		t.Fatalf("CSR with chain wasn't found in DB")
	}
	if csrsWithChain[0].CertificateChain != "" && csrsWithChain[1].CertificateChain != "" {
		t.Fatalf("CSR without chain wasn't found in DB")
	}

	bananaCSRWithChain, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(tu.BananaCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR with chain: %s", err)
	}
	if bananaCSRWithChain.CertificateChain == "" {
		t.Fatalf("Certificate chain was not added to CSR")
	}

	if err = database.RevokeCertificate(db.ByCSRPEM(tu.BananaCSR)); !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("Should have failed to revoke CSR.")
	}
	_, err = database.GetCertificateRequest(db.ByCSRPEM(tu.BananaCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}

	if err = database.RejectCertificateRequest(db.ByCSRPEM(tu.StrawberryCSR)); err != nil {
		t.Fatalf("Couldn't reject CSR: %s", err)
	}
	strawberryCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.StrawberryCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	if strawberryCSR.Status != "rejected" {
		t.Fatalf("CSR was not rejected")
	}
}

func TestCreateCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	InvalidCSR := strings.ReplaceAll(tu.AppleCSR, "M", "i")
	if _, err := database.CreateCertificateRequest(InvalidCSR, 0); err == nil {
		t.Fatalf("Expected error due to invalid CSR")
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	if _, err := database.CreateCertificateRequest(tu.AppleCSR, userID); err == nil {
		t.Fatalf("Expected error due to duplicate CSR")
	}
}

func TestGetCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	if _, err := database.GetCertificateRequest(db.ByCSRPEM("this is definitely not a csr")); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
	if _, err := database.GetCertificateRequest(db.ByCSRID(-1)); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}

	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("Failed to add certificate chain to CSR: %s", err)
	}
	if _, err := database.GetCertificateRequestAndChain(db.ByCSRPEM("still definitely not a csr")); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
	if _, err := database.GetCertificateRequestAndChain(db.ByCSRID(-1)); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
}

func TestDeleteCertificateRequestOld(t *testing.T) { //TODO: OVERLAP
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	err = database.DeleteCertificateRequest(db.ByCSRPEM("this is definitely not a csr"))
	if err == nil {
		t.Fatalf("Deleting a nonexistent CSR should return an error")
	}
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected a not found error when deleting a nonexistent CSR, got %s", err)
	}
	err = database.DeleteCertificateRequest(db.ByCSRID(-1))
	if err == nil {
		t.Fatalf("Deleting a nonexistent CSR should return an error")
	}
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected a not found error when deleting a nonexistent CSR, got %s", err)
	}
	csr, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Failed to get CSR: %s", err)
	}
	if csr.CSR != tu.AppleCSR {
		t.Fatalf("CSR was deleted from the DB")
	}
}

func TestRevokeCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	err = database.RevokeCertificate(db.ByCSRPEM("this is definitely not a csr"))
	if err == nil {
		t.Fatalf("Expected failure revoking nonexistent CSR")
	}
	err = database.RevokeCertificate(db.ByCSRID(-1))
	if err == nil {
		t.Fatalf("Expected failure revoking nonexistent CSR")
	}
	appleCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Failed to get CSR: %s", err)
	}
	if appleCSR.Status == "Revoked" {
		t.Fatalf("CSR Should not have been revoked")
	}
}

func TestRejectCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}

	err = database.RejectCertificateRequest(db.ByCSRPEM("this is definitely not a csr"))
	if err == nil {
		t.Fatalf("Expected failure rejecting nonexistent CSR")
	}
	err = database.RejectCertificateRequest(db.ByCSRID(-1))
	if err == nil {
		t.Fatalf("Expected failure rejecting nonexistent CSR")
	}

	appleCSR, err := database.GetCertificateRequest(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Failed to get CSR: %s", err)
	}
	if appleCSR.Status == "Rejected" {
		t.Fatalf("CSR Should not have been rejected")
	}
}

func TestCASNotShowingUpInCSRsTable(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	_, err = database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	csrs, err := database.ListCertificateRequestsWithoutCAS()
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if len(csrs) != 1 {
		t.Fatalf("Expected to see only 1 CSR, saw %d", len(csrs))
	}
	if csrs[0].Status != db.CSRStatusPending {
		t.Fatalf("Expected CSR to be in pending state, was %s", csrs[0].Status)
	}
	csrswithchain, err := database.ListCertificateRequestsWithCertificatesWithoutCAS(nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if len(csrswithchain) != 1 {
		t.Fatalf("Expected to see only 1 CSR, saw %d", len(csrswithchain))
	}
	if csrswithchain[0].Status != db.CSRStatusPending {
		t.Fatalf("Expected CSR to be in pending state, was %s", csrswithchain[0].Status)
	}
}

func TestCertificatesEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 1, got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.BananaCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if csrID != 2 {
		t.Fatalf("Couldn't complete Create: wrong csr id. expected 2, got %d", csrID)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
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
	if retrievedCSRWithCert.CertificateChain != tu.AppleCertificate+"\n"+tu.IntermediateCACertificate+"\n"+tu.RootCACertificate {
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSRWithCert, _ = database.GetCertificateRequestAndChain(db.ByCSRPEM(tu.BananaCSR))
	if retrievedCSRWithCert.CertificateChain != tu.BananaCertificate+"\n"+tu.IntermediateCACertificate+"\n"+tu.RootCACertificate {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSRWithCert.CertificateChain, tu.BananaCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	}
	err = database.RevokeCertificate(db.ByCSRPEM(tu.BananaCSR))
	if !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("Should have failed to revoke CSR that was signed outside of notary.")
	}
	chain, err := database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCertificate))
	if err != nil {
		t.Fatalf("Couldn't get certificate chain: %s", err)
	}
	if len(chain) != 3 {
		t.Fatalf("Expected 3 certificates in the chain, got %d", len(chain))
	}
	if chain[0].CertificatePEM != tu.AppleCertificate ||
		chain[1].CertificatePEM != tu.IntermediateCACertificate ||
		chain[2].CertificatePEM != tu.RootCACertificate {
		t.Fatalf("Certificate chain order or content incorrect")
	}

	err = database.DeleteCertificate(db.ByCertificatePEM(tu.AppleCertificate))
	if err != nil {
		t.Fatalf("Couldn't delete certificate: %s", err)
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCertificate))
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

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	if userID == 0 {
		t.Fatalf("CreateUser should return a valid user ID, got 0")
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
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
	if retrievedCSR.OwnerID != userID {
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
	if retrievedCSR.OwnerID != 0 {
		t.Fatalf("The User ID from the database should be set to 0 after deleting the user, got %d", retrievedCSR.OwnerID)
	}

	_, err = database.CreateCertificateRequest(tu.BananaCSR, userID)
	if err == nil {
		t.Fatalf("Creating a certificate request with a deleted user should return an error")
	}
}

func TestGetCertificateFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	database.CreateCertificateRequest(tu.AppleCSR, userID)                                                                                                                //nolint:errcheck
	database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCertificate+tu.IntermediateCACertificate+"some extra string"+tu.RootCACertificate) //nolint:errcheck

	cert, err := database.GetCertificate(db.ByCertificatePEM(tu.AppleCertificate))
	if err != nil || cert.CertificatePEM != tu.AppleCertificate {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, tu.AppleCertificate)
	}

	cert, err = database.GetCertificate(db.ByCertificateID(2))
	if err != nil || cert.CertificatePEM != tu.AppleCertificate {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", cert.CertificatePEM, tu.AppleCertificate)
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

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(tu.BananaCSR, userID)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	InvalidCert := strings.ReplaceAll(tu.BananaCertificate, "/", "+")
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), InvalidCert); err == nil {
		t.Fatalf("Expected adding certificate chain with invalid cert to fail")
	}
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.BananaCertificate); err == nil {
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
	if _, err := database.AddCertificateChainToCertificateRequest(db.ByCSRID(2), tu.BananaCertificate); err == nil {
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

	userID, err := database.CreateUser("testuser", "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.CreateCertificateRequest(tu.BananaCSR, userID)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCertificate+tu.IntermediateCACertificate+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("The certificate should have been uploaded successfully")
	}
	_, err = database.GetCertificateChain(db.ByCertificatePEM(tu.AppleCertificate))
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

// Authorities

func TestRootCertificateAuthorityEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(tu.RootCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if !ca.Enabled || ca.CertificateChain == "" {
		t.Fatalf("Certificate authority is not enabled or missing certificate")
	}

	err = database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), false)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Enabled {
		t.Fatalf("Certificate authority is enabled")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to disabled")
	}

	caRow, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CA to not be in the database: %s", err)
	}
	_, err = database.GetCertificateRequest(db.ByCSRID(caRow.CSRID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CSR to not be in the database: %s", err)
	}
	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(caRow.PrivateKeyID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected PrivateKey to not be in the database: %s", err)
	}
}

func TestCreateCertificateAuthorityExpired(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert, err := generateCACertificate(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Failed to generate expired CA data: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert+"\n"+expiredCACert, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csr, err := database.GetCertificateRequest(db.ByCSRPEM(expiredCACSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve CSR: %s", err)
	}
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if !ca.Enabled || ca.CertificateChain == "" {
		t.Fatalf("Certificate authority is not enabled or missing certificate")
	}
	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "notarytest.com")
	if err == nil {
		t.Fatalf("Expected signing to fail for expired CA: %s", err)
	}
}

func TestUpdateCertificateAuthorityEnabledStatusExpired(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert, err := generateCACertificate(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Failed to generate expired CA data: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert+"\n"+expiredCACert, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	err = database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(caID), false)
	if err != nil {
		t.Fatalf("Expected updating status to disabled to succeed for expired CA: %s", err)
	}

	err = database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(caID), true)
	if err != nil {
		t.Fatalf("Expected updating status to enabled to succeed for expired CA: %s", err)
	}
}

func TestIntermediateCertificateAuthorityEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(tu.IntermediateCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Enabled || ca.CertificateChain != "" {
		t.Fatalf("Certificate authority is enabled or has a certificate")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID), tu.IntermediateCACertificate+"\n"+tu.RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if !ca.Enabled || ca.CertificateChain != tu.IntermediateCACertificate+"\n"+tu.RootCACertificate {
		t.Fatalf("Certificate authority is not enabled or has a certificate")
	}

	err = database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), false)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Enabled {
		t.Fatalf("Certificate authority is enabled")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to disabled")
	}

	err = database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), true)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if !ca.Enabled {
		t.Fatalf("Certificate authority is not enabled")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to Enabled")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
}

func TestCertificateAuthorityFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateCertificateAuthority("", "", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, "", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, "nope", "", "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", tu.RootCAPrivateKey, tu.RootCACRL, "", 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("", tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, "", tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, "nope", tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, "", tu.RootCACertificate+"\n"+tu.RootCACertificate, 0)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}

	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(0), tu.RootCACertificate+"\n"+tu.RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(10), tu.RootCACertificate+"\n"+tu.RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(1), "")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(1), "no")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityCSRID(19))
	if err == nil {
		t.Fatalf("Should have failed to delete certificate authority")
	}
}

func TestSelfSignedCertificateList(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csrs, err := database.ListCertificateRequestsWithCertificates()
	if err != nil {
		t.Fatalf("Couldn't list certificates: %s", err)
	}
	if len(csrs) != 1 {
		t.Fatalf("%d certificates found when only 1 should be available", len(csrs))
	}
	if csrs[0].CertificateChain == "" {
		t.Fatalf("certificate should be available for CSR")
	}
}

func TestSigningCSRsFromSelfSignedCertificate(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign CSR: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
}

func TestSigningCSRsFromIntermediateCertificate(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, tu.IntermediateCACRL, tu.IntermediateCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected signed certificate chain to be 3 certificates long.")
	}
}

func TestSigningCSRFromUnsignedIntermediateCertificate(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	caID, err := database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(caID), "notarytest.com")
	if err == nil {
		t.Fatalf("Expected signing to fail: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain != "" {
		t.Fatalf("Certificate should not have been signed.")
	}
}

func TestSigningIntermediateCAByRootCA(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	rootCAID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	intermediateCAID, err := database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRPEM(tu.IntermediateCACSR), db.ByCertificateAuthorityDenormalizedID(rootCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	cas, err := database.ListDenormalizedCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if strings.Count(cas[0].CertificateChain, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("Expected root ca certificate chain to be 1 certificates long.")
	}
	if strings.Count(cas[1].CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected intermediate ca certificate chain to be 2 certificates long.")
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(intermediateCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected end certificate chain to be 3 certificates long.")
	}

	csrID, err = database.CreateCertificateRequest(tu.StrawberryCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(rootCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
}

func TestCertificateRevocationListsEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("testuser", "whateverpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	// The root CA has a valid CRL with no entries.
	rootCAID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	rootCA, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err := db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}

	// The intermediate CA has no CRL.
	intermediateCAID, err := database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	intermediateCA, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL != "" {
		t.Fatalf("CRL available for a CA without a certificate")
	}

	// The signed intermediate CA has a valid and empty CRL,
	// and its certificate has a CRLDistributionPoint extension that points to the root CA's CRL.
	err = database.SignCertificateRequest(db.ByCSRPEM(tu.IntermediateCACSR), db.ByCertificateAuthorityDenormalizedID(rootCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL == "" {
		t.Fatalf("CRL not available for a CA with a certificate")
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}
	certs, err := db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://notarytest.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://notarytest.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The signed CSR has a CRLDistributionPoint extension that points to the Intermediate CA's CRL with the correct hostname.
	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(intermediateCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(tu.AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://notarytest.com/api/v1/certificate_authorities/2/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://notarytest.com/api/v1/certificate_authorities/2/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the intermediate CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	AppleCertSerial := certs[0].SerialNumber.String()
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != AppleCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", AppleCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The signed certificate has a CRLDistributionPoint extension that points to the root CA's CRL with the correct hostname.
	csrID, err = database.CreateCertificateRequest(tu.StrawberryCSR, userID)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityDenormalizedID(rootCAID), "notarytest.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://notarytest.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://notarytest.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	StrawberryCertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", StrawberryCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The revoked intermediate CA's certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRPEM(intermediateCA.CSRPEM))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	certs, err = db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	IntermediateCACertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL should have 2 entries, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
	if crl.RevokedCertificateEntries[1].SerialNumber.String() != IntermediateCACertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
}

func generateCACertificate(notAfter time.Time) (csrPEM string, keyPEM string, crlPEM string, certPEM string, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to generate CA key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Expired Root CA",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CSR: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               csrTemplate.Subject,
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse CA cert: %w", err)
	}

	now := time.Now()
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: []pkix.RevokedCertificate{},
		ThisUpdate:          now.Add(-24 * time.Hour),
		NextUpdate:          now.Add(30 * 24 * time.Hour),
		Number:              big.NewInt(1),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CRL: %w", err)
	}

	keyPEM = encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))
	certPEM = encodePEM("CERTIFICATE", caCertDER)
	csrPEM = encodePEM("CERTIFICATE REQUEST", csrDER)
	crlPEM = encodePEM("X509 CRL", crlDER)

	return csrPEM, keyPEM, crlPEM, certPEM, nil
}

func encodePEM(blockType string, derBytes []byte) string {
	var b strings.Builder
	_ = pem.Encode(&b, &pem.Block{Type: blockType, Bytes: derBytes})
	return b.String()
}
func TestEncryptionKeyEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	encryptionKey, err := database.GetEncryptionKey()
	if err != nil {
		t.Fatalf("Couldn't get encryption key: %s", err)
	}
	if len(encryptionKey) == 0 {
		t.Fatalf("Expected an encryption key to be created on DB")
	}

	err = database.CreateEncryptionKey([]byte("test"))
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Expected an already exists error, got %s", err)
	}

	err = database.DeleteEncryptionKey()
	if err != nil {
		t.Fatalf("Couldn't delete encryption key: %s", err)
	}

	_, err = database.GetEncryptionKey()
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected a not found error, got %s", err)
	}

	err = database.CreateEncryptionKey([]byte("test1"))
	if err != nil {
		t.Fatalf("Couldn't create encryption key: %s", err)
	}

	// Get and verify the newly created encryption key
	if encryptionKey, err = database.GetEncryptionKey(); err != nil {
		t.Fatalf("Couldn't get encryption key: %s", err)
	}
	if string(encryptionKey) != "test1" {
		t.Fatalf("Encryption key is not 'test1'")
	}
}

func TestJWTSecretEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	jwtSecret, err := database.GetJWTSecret()
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}
	if jwtSecret != nil {
		t.Fatalf("JWT secret is not nil")
	}

	err = database.CreateJWTSecret([]byte("test"))
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret, err = database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(jwtSecret) != "test" {
		t.Fatalf("JWT secret is not 'test'")
	}

	err = database.CreateJWTSecret([]byte("test1"))
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Expected an already exists error, got %s", err)
	}

	err = database.DeleteJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't delete JWT secret: %s", err)
	}

	err = database.CreateJWTSecret([]byte("test2"))
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret, err = database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(jwtSecret) != "test2" {
		t.Fatalf("JWT secret is not 'test2'")
	}
}

func TestJWTSecretEncryption(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	originalSecret := []byte("super-secret-jwt-key")
	err := database.CreateJWTSecret(originalSecret)
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret := db.JWTSecret{ID: 1}
	row := database.Conn.PlainDB().QueryRow("SELECT * FROM jwt_secret WHERE id = ?", jwtSecret.ID)
	err = row.Scan(&jwtSecret.ID, &jwtSecret.EncryptedSecret)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if jwtSecret.EncryptedSecret == string(originalSecret) {
		t.Fatal("JWT secret is stored in plaintext!")
	}

	decryptedSecret, err := database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(decryptedSecret) != string(originalSecret) {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			string(decryptedSecret), string(originalSecret))
	}

	decryptedManually, err := encryption.Decrypt(jwtSecret.EncryptedSecret, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != string(originalSecret) {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, string(originalSecret))
	}
}

func TestPrivateKeysEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}

	pkID, err := database.CreatePrivateKey(tu.RootCAPrivateKey)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}
	if pkID != 1 {
		t.Fatalf("Couldn't create private key: expected pk id 1, got %d", pkID)
	}

	pk, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if pk.PrivateKeyPEM != tu.RootCAPrivateKey {
		t.Fatalf("Private key is not correct")
	}

	err = database.DeletePrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't delete private key: %s", err)
	}

	pk, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}
	if pk != nil {
		t.Fatalf("Private key is not nil")
	}
}

func TestPrivateKeyFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreatePrivateKey("")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}
	_, err = database.CreatePrivateKey("nope")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}

	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(0))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(10))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
}

func TestPrivateKeyEncryption(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	pkID, err := database.CreatePrivateKey(tu.RootCAPrivateKey)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}

	pk := db.PrivateKey{PrivateKeyID: pkID}

	row := database.Conn.PlainDB().QueryRow("SELECT * FROM private_keys WHERE private_key_id = ?", pk.PrivateKeyID)
	err = row.Scan(&pk.PrivateKeyID, &pk.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if pk.PrivateKeyPEM == tu.RootCAPrivateKey {
		t.Fatal("Private key is stored in plaintext!")
	}

	decryptedPK, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(pkID))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if decryptedPK.PrivateKeyPEM != tu.RootCAPrivateKey {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			decryptedPK.PrivateKeyPEM, tu.RootCAPrivateKey)
	}

	decryptedManually, err := encryption.Decrypt(pk.PrivateKeyPEM, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != tu.RootCAPrivateKey {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, tu.RootCAPrivateKey)
	}
}
func TestUsersEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userID, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if userID != 1 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", userID)
	}

	userID, err = database.CreateUser("norman", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if userID != 2 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", userID)
	}

	res, err := database.ListUsers()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 2 {
		t.Fatalf("One or more users weren't found in DB")
	}

	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("NumUsers didn't return the correct number of users")
	}

	retrievedUser, err := database.GetUser(db.ByUsername("admin"))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}

	retrievedUser, err = database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, "pw123"); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}

	if err = database.DeleteUser(db.ByUserID(1)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = database.ListUsers()
	if len(res) != 1 {
		t.Fatalf("users weren't deleted from the DB properly")
	}

	err = database.UpdateUserPassword(db.ByUserID(2), "thebestpassword")
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedUser, _ = database.GetUser(db.ByUsername("norman"))
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, "thebestpassword"); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}

func TestCreateUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}
	_, err = database.CreateUser("admin", "pw456", 1)
	if err == nil {
		t.Fatalf(
			"An error should have been returned when creating a user with a duplicate username.",
		)
	}
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("An error should have been returned when creating a user with a duplicate username.")
	}
	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.GetUser(db.ByUserID(2))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}
	_, err = database.CreateUser("", "pw456", 0)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with an empty username.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an empty username.")
	}
	num, err = database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.CreateUser("newUser", "", 0)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with a nil password.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with a nil password.")
	}
	num, err = database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.CreateUser("newUser", "pw456", 32)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with an invalid role ID.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an invalid role ID.")
	}
}

func TestGetUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.GetUser(db.ByUserID(2))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}

	_, err = database.GetUser(db.ByUsername("admin2"))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}
}

func TestUpdateUserPasswordFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	originalPassword := "pw123"
	_, err := database.CreateUser("admin", originalPassword, 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	err = database.UpdateUserPassword(db.ByUserID(2), "pw456")
	if err == nil {
		t.Fatalf("An error should have been returned when updating a non-existent user.")
	}
	retrievedUser, err := database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete GetUser: %s", err)
	}
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, originalPassword); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}

	err = database.UpdateUserPassword(db.ByUserID(1), "")
	if err == nil {
		t.Fatalf("An error should have been returned when updating a user with an empty password.")
	}
	if !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("An ErrInvalidInput should have been returned when updating a user with an empty password.")
	}
	retrievedUser, err = database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete GetUser: %s", err)
	}
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, originalPassword); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
}

func TestDeleteUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}
	_, err = database.CreateUser("normal", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	err = database.DeleteUser(db.ByUserID(3))
	if err == nil {
		t.Fatalf("An error should have been returned when deleting a non-existent user.")
	}

	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("The number of users should be 2.")
	}
}
