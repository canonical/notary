package acme

import (
	"errors"
	"fmt"
	"strconv"
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
// ACME issuance is a long-running, in-memory operation: notary hands a CSR to
// lego, which polls a DNS-01 challenge for as long as DNS propagation takes. If
// the node running it dies, the request is left sitting at 'Outstanding' with
// no indication that anything went wrong, and nothing will ever pick it up
// again. There is no safe way to resume — the challenge state lives in the dead
// process — so the outcome has to be reported rather than retried.
//
// The reconciler makes that possible by recording each attempt in the database
// before it starts and clearing it when it finishes. An attempt that outlives
// its process is an orphan, and the request behind it is failed.
type Reconciler struct {
	mu sync.Mutex
	// database is nil until Attach is called. The cluster node has to exist
	// before its leadership hook can be registered, but the replicated database
	// can only be opened through that node, so the reconciler is necessarily
	// built before it has anything to reconcile against.
	database *db.DatabaseRepository
	// nodeID is this node's dqlite node ID in decimal, or empty when clustering
	// is disabled.
	nodeID string
	// live holds the CSR IDs this process is currently polling. It is what
	// separates an orphan from an attempt that is still running here: an attempt
	// row alone cannot say, because a node keeps its dqlite ID across a restart.
	live map[int64]struct{}
	// wasLeader records whether this node held leadership at the previous
	// observation, so that reconciliation runs on the transition rather than on
	// every tick of the roles adjustment loop.
	wasLeader bool

	logger *zap.Logger
}

// NewReconciler builds a reconciler that does nothing until Attach is called.
//
// A reconciler has to exist before the cluster node it belongs to, because the
// node needs its leadership hook at construction time — but the replicated
// database and the system logger only exist once that node is running. Attach
// closes that gap.
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
// failed. Either way the attempt is no longer in flight, and leaving the row
// behind would make a later reconciliation fail a request that already has its
// answer.
//
// It returns nothing so callers can defer it: by the time it runs the outcome
// of the attempt is already settled, and a failure to clean up is a logged
// problem rather than one the caller can act on.
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

// OnRolesAdjustment is the hook go-dqlite runs on every node each time cluster
// roles are re-evaluated. It reconciles only when this node has just become the
// leader: ACME issuance runs on the leader alone, so a new leader inherits
// whatever the previous one left behind.
func (r *Reconciler) OnRolesAdjustment(leaderID uint64) error {
	r.mu.Lock()
	if r.database == nil {
		// Not armed yet. Leadership is deliberately not recorded, so the first
		// observation after Attach still counts as a transition.
		r.mu.Unlock()
		return nil
	}
	isLeader := strconv.FormatUint(leaderID, 10) == r.nodeID
	wasLeader := r.wasLeader
	r.wasLeader = isLeader
	logger := r.logger
	r.mu.Unlock()

	if !isLeader || wasLeader {
		return nil
	}

	logger.Info("became cluster leader, reconciling ACME issuance attempts")

	return r.Reconcile()
}

// Reconcile fails every certificate request whose ACME issuance attempt is not
// running in this process.
//
// Callers must only invoke this where every attempt recorded elsewhere is known
// to be dead: on becoming the leader of a cluster where issuance is
// leader-only, or at startup of an unclustered deployment, where this process
// is the only one there has ever been.
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

		// The request is failed before the attempt is cleared. If this node dies
		// in between, the attempt is still recorded and the next reconciliation
		// repeats the work; clearing first would lose the request instead.
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
