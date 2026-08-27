package acme

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// FailureReason is recorded against a request failed by the reconciler. The
// status itself carries no free-text field, so the reason exists to give the
// log line and the audit trail something an operator can search for.
const FailureReason = "issuance was interrupted by an internal failure"

// ErrAttemptInProgress is returned by BeginAttempt when issuance for the same
// certificate request is already running. Issuance is not idempotent — each
// attempt registers its own DNS-01 challenge — so a second one has to be
// refused rather than allowed to race the first.
var ErrAttemptInProgress = errors.New("an ACME issuance attempt is already in progress for this certificate request")

// Reconciler owns the lifecycle of ACME issuance attempts.
//
// ACME issuance is a long-running, in-memory operation. If the process running
// it dies, the request is left sitting at 'Outstanding' with no indication that
// anything went wrong. There is no safe way to resume, so leftover attempts are
// failed on the designated issuer's restart (or at startup of an unclustered
// process). Heartbeats and Raft leadership are not consulted.
type Reconciler struct {
	mu       sync.Mutex
	database *db.DatabaseRepository
	nodeID   string
	live     map[int64]struct{}
	logger   *zap.Logger
}

// NewReconciler builds a reconciler that does nothing until Attach is called.
func NewReconciler() *Reconciler {
	return &Reconciler{
		live:   make(map[int64]struct{}),
		logger: zap.NewNop(),
	}
}

// Attach arms the reconciler against the database it should reconcile.
//
// nodeID is this node's dqlite node ID in decimal, or empty for an unclustered
// deployment, which has no node IDs.
func (r *Reconciler) Attach(database *db.DatabaseRepository, logger *zap.Logger, nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.database = database
	r.logger = logger
	r.nodeID = nodeID
}

// BeginAttempt records that this node is about to hand csrID to an ACME
// provider. It must be called before issuance starts and paired with
// EndAttempt.
func (r *Reconciler) BeginAttempt(csrID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.database == nil {
		return errors.New("the ACME issuance reconciler is not attached to a database")
	}
	if _, running := r.live[csrID]; running {
		return fmt.Errorf("%w: certificate request %d", ErrAttemptInProgress, csrID)
	}

	if err := r.database.CreateACMEIssuanceAttempt(csrID, r.nodeID, time.Now()); err != nil {
		return err
	}
	r.live[csrID] = struct{}{}

	return nil
}

// EndAttempt clears the record for a finished attempt, whether it succeeded or
// failed.
func (r *Reconciler) EndAttempt(csrID int64) {
	r.mu.Lock()
	delete(r.live, csrID)
	database := r.database
	logger := r.logger
	r.mu.Unlock()

	if database == nil {
		return
	}
	if err := database.DeleteACMEIssuanceAttempt(csrID); err != nil && !errors.Is(err, db.ErrNotFound) {
		logger.Error("failed to clear finished ACME issuance attempt", zap.Error(err), zap.Int64("csr_id", csrID))
	}
}

// Reconcile fails every certificate request whose ACME issuance attempt is not
// running in this process. Callers must only invoke this on the designated
// issuer (or an unclustered process), where every leftover attempt is known to
// be dead.
func (r *Reconciler) Reconcile() error {
	r.mu.Lock()
	database := r.database
	logger := r.logger
	r.mu.Unlock()

	if database == nil {
		return errors.New("the ACME issuance reconciler is not attached to a database")
	}

	attempts, err := database.ListACMEIssuanceAttempts()
	if err != nil {
		return fmt.Errorf("failed to list ACME issuance attempts: %w", err)
	}

	for _, attempt := range attempts {
		r.mu.Lock()
		_, running := r.live[attempt.CSRID]
		r.mu.Unlock()
		if running {
			continue
		}

		if err := database.FailCertificateRequest(attempt.CSRID); err != nil && !errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("failed to fail interrupted certificate request %d: %w", attempt.CSRID, err)
		}
		if err := database.DeleteACMEIssuanceAttempt(attempt.CSRID); err != nil && !errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("failed to clear interrupted ACME issuance attempt %d: %w", attempt.CSRID, err)
		}

		logger.Warn("failed a certificate request whose ACME issuance was interrupted",
			zap.Int64("csr_id", attempt.CSRID),
			zap.String("owner_node_id", attempt.NodeID),
			zap.String("reason", FailureReason),
		)
	}

	return nil
}
