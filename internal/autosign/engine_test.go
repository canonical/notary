package autosign

import (
	"context"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

func TestEngineNoPolicies(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	// Create a user and CSR without any policy
	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "password", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatal(err)
	}

	engine := New(database, zap.NewNop(), "example.com")
	engine.pollInterval = 100 * time.Millisecond
	engine.processOutstandingCSRs()

	// CSR should still be Outstanding since no policies exist
	csrs, err := database.ListOutstandingCSRsExcludingCAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(csrs) != 1 {
		t.Fatalf("expected 1 outstanding CSR, got %d", len(csrs))
	}
}

func TestEngineNoOutstandingCSRs(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "password", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed CA
	caID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userEmail)
	if err != nil {
		t.Fatal(err)
	}

	// Create auto-sign policy
	_, err = database.CreateAutoSignPolicy(db.AutoSignPolicy{
		CertificateAuthorityID: caID,
		Enabled:                true,
	})
	if err != nil {
		t.Fatal(err)
	}

	engine := New(database, zap.NewNop(), "example.com")
	engine.pollInterval = 100 * time.Millisecond
	engine.processOutstandingCSRs()

	// No CSRs exist, nothing should happen
}

func TestEngineAutoSignsOutstandingCSR(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "password", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed CA
	caID, err := database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userEmail)
	if err != nil {
		t.Fatal(err)
	}

	// Create auto-sign policy
	_, err = database.CreateAutoSignPolicy(db.AutoSignPolicy{
		CertificateAuthorityID: caID,
		Enabled:                true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create an outstanding CSR
	csrID, err := database.CreateCertificateRequest(tu.AppleCSR, userEmail)
	if err != nil {
		t.Fatal(err)
	}

	engine := New(database, zap.NewNop(), "example.com")
	engine.pollInterval = 100 * time.Millisecond
	engine.processOutstandingCSRs()

	// CSR should now be Active with a certificate chain
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Status != "Active" {
		t.Errorf("expected status Active, got %s", csr.Status)
	}
	if csr.CertificateChain == "" {
		t.Error("expected certificate chain to be set")
	}
}

func TestEngineRunWithContextCancellation(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	engine := New(database, zap.NewNop(), "example.com")
	engine.pollInterval = 50 * time.Millisecond

	// Run in background and cancel quickly
	ctx, cancel := context.WithCancel(context.Background())
	go engine.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Should stop cleanly without panic
}
