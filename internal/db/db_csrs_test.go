package db_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCSRsEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	if csrID != 1 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.BananaCSR, userEmail)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	if csrID != 2 {
		t.Fatalf("Couldn't complete Create: expected user id 2, but got %d", csrID)
	}
	csrID, err = database.CreateCertificateRequest(tu.StrawberryCSR, userEmail)
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
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.BananaCSR), tu.BananaCert+tu.IntermediateCert+tu.RootCert)
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

	csrsWithChain, err := database.ListCertificateRequestWithCertificates()
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
	if strawberryCSR.Status != "Rejected" {
		t.Fatalf("CSR was not rejected")
	}
}

func TestCreateCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	InvalidCSR := strings.ReplaceAll(tu.AppleCSR, "M", "i")
	if _, err := database.CreateCertificateRequest(InvalidCSR, ""); err == nil {
		t.Fatalf("Expected error due to invalid CSR")
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	if _, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail); err == nil {
		t.Fatalf("Expected error due to duplicate CSR")
	}
}

func TestGetCertificateRequestFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatalf("Failed to create CSR: %s", err)
	}
	if _, err := database.GetCertificateRequest(db.ByCSRPEM("this is definitely not a csr")); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
	if _, err := database.GetCertificateRequest(db.ByCSRID(-1)); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}

	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(tu.AppleCSR), tu.AppleCert+tu.IntermediateCert+tu.RootCert)
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

func TestDeleteCertificateRequest(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
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

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
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

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
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

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "testpassword", 0)
	if err != nil {
		t.Fatalf("Couldn't create user: %s", err)
	}

	_, err = database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userEmail)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	_, err = database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userEmail)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
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
	if csrs[0].Status != "Outstanding" {
		t.Fatalf("Expected CSR to be in pending state, was %s", csrs[0].Status)
	}
	filter := &db.CSRFilter{}
	csrswithchain, err := database.ListCertificateRequestWithCertificatesWithoutCAS(filter)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}
	if len(csrswithchain) != 1 {
		t.Fatalf("Expected to see only 1 CSR, saw %d", len(csrswithchain))
	}
	if csrswithchain[0].Status != "Outstanding" {
		t.Fatalf("Expected CSR to be in pending state, was %s", csrswithchain[0].Status)
	}
}
