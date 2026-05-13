package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func mustCreateTestCA(t *testing.T, database *db.DatabaseRepository, csr, key, crl, cert string) int64 {
	t.Helper()
	userEmail := "testuser@example.com"
	// User may already exist if test uses multiple CAs in same DB
	_, err := database.CreateUser(userEmail, "whateverpassword", 0)
	if err != nil && !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Couldn't create user: %s", err)
	}
	caID, err := database.CreateCertificateAuthority(csr, key, crl, cert, userEmail)
	if err != nil {
		t.Fatalf("Couldn't create CA: %s", err)
	}
	return caID
}

func mustCreatePolicy(t *testing.T, database *db.DatabaseRepository, caID int64, enabled bool) {
	t.Helper()
	policy := db.AutoSignPolicy{
		CertificateAuthorityID: caID,
		Enabled:                enabled,
	}
	_, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("Couldn't create policy: %s", err)
	}
}

func TestCreateAutoSignPolicy(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	policy := db.AutoSignPolicy{
		CertificateAuthorityID:  caID,
		Enabled:                 true,
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	}

	id, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	got, err := database.GetAutoSignPolicy(caID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if got.PolicyID != id {
		t.Errorf("expected policy ID %d, got %d", id, got.PolicyID)
	}
	if got.CertificateAuthorityID != policy.CertificateAuthorityID {
		t.Errorf("expected CA ID %d, got %d", policy.CertificateAuthorityID, got.CertificateAuthorityID)
	}
	if got.Enabled != policy.Enabled {
		t.Errorf("expected enabled %t, got %t", policy.Enabled, got.Enabled)
	}
	if got.CertificateValidityDays != policy.CertificateValidityDays {
		t.Errorf("expected validity %d, got %d", policy.CertificateValidityDays, got.CertificateValidityDays)
	}
	if got.CertificateLimit != policy.CertificateLimit {
		t.Errorf("expected limit %d, got %d", policy.CertificateLimit, got.CertificateLimit)
	}
}

func TestCreateAutoSignPolicyDuplicateCA(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	policy := db.AutoSignPolicy{
		CertificateAuthorityID: caID,
	}

	_, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error on first create: %v", err)
	}

	_, err = database.CreateAutoSignPolicy(policy)
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestGetAutoSignPolicy(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	policy := db.AutoSignPolicy{
		CertificateAuthorityID: caID,
		Enabled:                true,
	}

	_, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	got, err := database.GetAutoSignPolicy(caID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if !got.Enabled {
		t.Error("expected policy to be enabled")
	}

	_, err = database.GetAutoSignPolicy(999)
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateAutoSignPolicy(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	policy := db.AutoSignPolicy{
		CertificateAuthorityID:  caID,
		Enabled:                 true,
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	}

	_, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	updated := db.AutoSignPolicy{
		CertificateAuthorityID:  caID,
		Enabled:                 false,
		CertificateValidityDays: 30,
		CertificateLimit:        10,
	}

	err = database.UpdateAutoSignPolicy(updated)
	if err != nil {
		t.Fatalf("failed to update policy: %v", err)
	}

	got, err := database.GetAutoSignPolicy(caID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if got.Enabled {
		t.Error("expected disabled")
	}
	if got.CertificateValidityDays != 30 {
		t.Errorf("expected validity 30, got %d", got.CertificateValidityDays)
	}
	if got.CertificateLimit != 10 {
		t.Errorf("expected limit 10, got %d", got.CertificateLimit)
	}
}

func TestDeleteAutoSignPolicy(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	policy := db.AutoSignPolicy{
		CertificateAuthorityID: caID,
	}

	_, err := database.CreateAutoSignPolicy(policy)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	err = database.DeleteAutoSignPolicy(caID)
	if err != nil {
		t.Fatalf("failed to delete policy: %v", err)
	}

	_, err = database.GetAutoSignPolicy(caID)
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestListActiveAutoSignPolicies(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	ca1 := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)
	ca2 := mustCreateTestCA(t, database, tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, tu.IntermediateCACRL, tu.IntermediateCACertificate+"\n"+tu.RootCACertificate)

	mustCreatePolicy(t, database, ca1, true)
	mustCreatePolicy(t, database, ca2, false)

	policies, err := database.ListActiveAutoSignPolicies()
	if err != nil {
		t.Fatalf("failed to list policies: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("expected 1 active policy, got %d", len(policies))
	}
	if policies[0].CertificateAuthorityID != ca1 {
		t.Errorf("expected CA %d, got %d", ca1, policies[0].CertificateAuthorityID)
	}
}

func TestCascadeDeleteOnCARemoval(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)

	mustCreatePolicy(t, database, caID, true)

	err := database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(caID))
	if err != nil {
		t.Fatalf("failed to delete CA: %v", err)
	}

	_, err = database.GetAutoSignPolicy(caID)
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected policy deleted, but got %v", err)
	}
}

func TestListOutstandingCSRsExcludingCAs(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "whateverpassword", 0)
	if err != nil {
		t.Fatal(err)
	}

	outstandingID, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatal(err)
	}
	rejectedID, err := database.CreateCertificateRequest(tu.StrawberryCSR, userEmail)
	if err != nil {
		t.Fatal(err)
	}
	err = database.RejectCertificateRequest(db.ByCSRID(rejectedID))
	if err != nil {
		t.Fatal(err)
	}

	caID := mustCreateTestCA(t, database, tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate)
	caRow, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(caID))
	if err != nil {
		t.Fatal(err)
	}
	caCSR, err := database.GetCertificateRequest(db.ByCSRID(caRow.CSRID))
	if err != nil {
		t.Fatal(err)
	}

	csrs, err := database.ListOutstandingCSRsExcludingCAs()
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}

	if len(csrs) != 1 {
		t.Errorf("expected 1 CSR, got %d", len(csrs))
	}
	if csrs[0].CSR_ID != outstandingID {
		t.Errorf("expected ID %d, got %d", outstandingID, csrs[0].CSR_ID)
	}
	if csrs[0].Status != "Outstanding" {
		t.Errorf("expected Outstanding, got %s", csrs[0].Status)
	}

	for _, csr := range csrs {
		if csr.CSR_ID == caCSR.CSR_ID {
			t.Error("CA CSR should be excluded")
		}
	}
}