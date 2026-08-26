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
// those would mean every leader election destroyed the queue.
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

// Leadership can move away and come back while an issuance this process started
// is still polling. Reconciling must not fail work that is still running here.
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

// Reconciliation runs on the transition to leadership, not on every tick of the
// roles adjustment loop, and never on a node that is not the leader.
func TestOnRolesAdjustmentReconcilesOnlyOnBecomingLeader(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	reconciler := acme.NewReconciler()
	reconciler.Attach(database, zap.NewNop(), "7")

	orphaned := mustCreateCertificateRequest(t, database, tu.AppleCSR)
	if err := database.CreateACMEIssuanceAttempt(orphaned, "3", time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}

	// Another node leads: nothing here is this node's to clean up.
	if err := reconciler.OnRolesAdjustment(3); err != nil {
		t.Fatalf("couldn't handle roles adjustment: %s", err)
	}
	if status := mustGetStatus(t, database, orphaned); status != "Outstanding" {
		t.Fatalf("expected a follower to reconcile nothing, got %q", status)
	}

	// This node takes over and inherits the orphan.
	if err := reconciler.OnRolesAdjustment(7); err != nil {
		t.Fatalf("couldn't handle roles adjustment: %s", err)
	}
	if status := mustGetStatus(t, database, orphaned); status != db.StatusFailed {
		t.Fatalf("expected a new leader to fail the orphaned request, got %q", status)
	}

	// Still leading on the next tick, so there is no transition and no second
	// pass: an attempt started since must be left alone.
	stillRunning := mustCreateCertificateRequest(t, database, tu.BananaCSR)
	if err := database.CreateACMEIssuanceAttempt(stillRunning, "7", time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}
	if err := reconciler.OnRolesAdjustment(7); err != nil {
		t.Fatalf("couldn't handle roles adjustment: %s", err)
	}
	if status := mustGetStatus(t, database, stillRunning); status != "Outstanding" {
		t.Errorf("expected no reconciliation without a leadership transition, got %q", status)
	}
}

// Leadership moving is not the same as the node that was issuing dying. A new
// leader must leave a live peer's attempt alone, or it abandons issuance that is
// still in progress and fails a request that is about to succeed.
func TestReconcileLeavesAttemptsOwnedByALiveMemberAlone(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	const peerNodeID = "7"
	if err := database.CreateACMEIssuanceAttempt(csrID, peerNodeID, time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}

	// The peer is reporting for duty, so its attempt is not an orphan.
	if err := database.RecordClusterMemberHeartbeat(peerNodeID, "10.0.0.7:9000", false, time.Now().UTC()); err != nil {
		t.Fatalf("couldn't record the peer's heartbeat: %s", err)
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status == "Failed" {
		t.Error("a live member's issuance attempt was failed by another node's reconciliation")
	}
	attempts, err := database.ListACMEIssuanceAttempts()
	if err != nil {
		t.Fatalf("couldn't list attempts: %s", err)
	}
	if len(attempts) != 1 {
		t.Errorf("got %d attempts, want the peer's to be left in place", len(attempts))
	}
}

// Once that peer stops reporting, the attempt is an orphan like any other.
func TestReconcileFailsAttemptsOwnedByAMemberThatStoppedReporting(t *testing.T) {
	reconciler, database := mustAttachedReconciler(t)
	csrID := mustCreateCertificateRequest(t, database, tu.AppleCSR)

	const peerNodeID = "7"
	if err := database.CreateACMEIssuanceAttempt(csrID, peerNodeID, time.Now()); err != nil {
		t.Fatalf("couldn't record ACME issuance attempt: %s", err)
	}
	stale := time.Now().UTC().Add(-2 * db.OfflineThreshold)
	if err := database.RecordClusterMemberHeartbeat(peerNodeID, "10.0.0.7:9000", false, stale); err != nil {
		t.Fatalf("couldn't record the peer's heartbeat: %s", err)
	}

	if err := reconciler.Reconcile(); err != nil {
		t.Fatalf("couldn't reconcile: %s", err)
	}

	if status := mustGetStatus(t, database, csrID); status != "Failed" {
		t.Errorf("got status %q, want Failed", status)
	}
}
