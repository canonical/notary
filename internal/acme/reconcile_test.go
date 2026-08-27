package acme_test

import (
	"errors"
	"testing"
	"time"

	"github.com/canonical/notary/internal/acme"
	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

// mustAttachedReconciler returns a reconciler armed against an empty database,
// configured as an unclustered node.
func mustAttachedReconciler(t *testing.T) (*acme.Reconciler, *db.DatabaseRepository) {
	t.Helper()

	database := tu.MustPrepareEmptyDB(t)
	reconciler := acme.NewReconciler()
	reconciler.Attach(database, zap.NewNop(), "")

	return reconciler, database
}

// mustCreateCertificateRequest inserts a certificate request and returns its ID.
func mustCreateCertificateRequest(t *testing.T, database *db.DatabaseRepository, csr string) int64 {
	t.Helper()

	id, err := database.CreateCertificateRequest(csr, "admin@canonical.com")
	if err != nil {
		t.Fatalf("couldn't create certificate request: %s", err)
	}

	return id
}

func mustGetStatus(t *testing.T, database *db.DatabaseRepository, csrID int64) string {
	t.Helper()

	csr, err := database.GetCertificateRequest(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("couldn't get certificate request %d: %s", csrID, err)
	}

	return csr.Status
}

// An attempt row that no process is running is the signature of a node that
// died mid-issuance. The request behind it can never complete, so it has to be
// reported rather than left pending forever.
func TestReconcileFailsOrphanedAttempts(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	// Written directly, standing in for an attempt recorded by a process that is
	// no longer running.
	if err := database.CreateACMEIssuanceAttempt(csrID, "7", time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status != db.StatusFailed {
		t.Errorf("expected the interrupted request to be %q, got %q", db.StatusFailed, status)
	}

	attempts, err := database.ListACMEIssuanceAttempts()
	if err != nil {
		t.Fatalf("couldn't list ACME issuance attempts: %s", err)
	}
	if len(attempts) != 0 {
		t.Errorf("expected the reconciled attempt to be cleared, got %d attempts", len(attempts))
	}
}

// This is the safety property the whole design rests on: a request that was
// never handed to an ACME provider is an ordinary pending request. Failing
// those would mean every issuer restart destroyed the queue.
func TestReconcileLeavesRequestsWithoutAttemptsAlone(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status != "Outstanding" {
		t.Errorf("expected an untouched request to stay Outstanding, got %q", status)
	}
}

// An issuer restart must not fail work that is still running in this process.
func TestReconcileSkipsAttemptsRunningInThisProcess(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	if err := reconciler.BeginAttempt(csrID); err != nil {
		t.Fatalf("couldn't begin ACME issuance attempt: %s", err)
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status != "Outstanding" {
		t.Errorf("expected a live attempt's request to stay Outstanding, got %q", status)
	}

	attempts, err := database.ListACMEIssuanceAttempts()
	if err != nil {
		t.Fatalf("couldn't list ACME issuance attempts: %s", err)
	}
	if len(attempts) != 1 {
		t.Errorf("expected the live attempt to survive reconciliation, got %d attempts", len(attempts))
	}
}

// An attempt that finished has its answer already, whatever that answer was.
// Leaving the row behind would let a later reconciliation overwrite it.
func TestEndAttemptClearsTheRecord(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	if err := reconciler.BeginAttempt(csrID); err != nil {
		t.Fatalf("couldn't begin ACME issuance attempt: %s", err)
	}
	reconciler.EndAttempt(csrID)

	attempts, err := database.ListACMEIssuanceAttempts()
	if err != nil {
		t.Fatalf("couldn't list ACME issuance attempts: %s", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected the finished attempt to be cleared, got %d attempts", len(attempts))
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}
	if status := mustGetStatus(t, database, csrID); status != "Outstanding" {
		t.Errorf("expected a finished attempt's request to be untouched, got %q", status)
	}
}

// Each attempt registers its own DNS-01 challenge, so a second concurrent one
// would race the first rather than duplicate it harmlessly.
func TestBeginAttemptRefusesAConcurrentAttempt(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	if err := reconciler.BeginAttempt(csrID); err != nil {
		t.Fatalf("couldn't begin ACME issuance attempt: %s", err)
	}

	err := reconciler.BeginAttempt(csrID)
	if !errors.Is(err, acme.ErrAttemptInProgress) {
		t.Errorf("expected ErrAttemptInProgress for a second concurrent attempt, got %v", err)
	}
}

// An attempt can be interrupted after issuance actually succeeded but before its
// record was cleared. The certificate is real, so the settled outcome wins.
func TestReconcileDoesNotOverwriteASettledOutcome(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	if err := database.CreateACMEIssuanceAttempt(csrID, "7", time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}
	if err := database.RejectCertificateRequest(db.ByCSRID(csrID)); err != nil {
		t.Fatalf("couldn't reject certificate request: %s", err)
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status != "Rejected" {
		t.Errorf("expected the settled status to survive reconciliation, got %q", status)
	}
}
