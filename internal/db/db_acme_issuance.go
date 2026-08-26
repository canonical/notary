package db

import (
	"fmt"
	"time"
)

// StatusFailed marks a certificate request whose issuance was interrupted and
// cannot be resumed. It is terminal: the request carries no certificate and
// notary will not retry it. Requesting a new certificate means submitting a new
// request.
const StatusFailed = "Failed"

// CreateACMEIssuanceAttempt records that this node is about to hand csrID to an
// ACME provider. The row must be written before the attempt starts: it is the
// only durable evidence that issuance was in flight if the node dies mid-poll.
//
// nodeID is the dqlite node ID of the node running the attempt, in decimal. It
// is empty for an unclustered deployment, which has no node IDs.
func (db *DatabaseRepository) CreateACMEIssuanceAttempt(csrID int64, nodeID string, startedAt time.Time) error {
	if csrID == 0 {
		return fmt.Errorf("failed to create ACME issuance attempt: %w: CSR ID is required", ErrInvalidInput)
	}

	row := ACMEIssuanceAttempt{
		CSRID:     csrID,
		NodeID:    nodeID,
		StartedAt: startedAt.Unix(),
	}
	_, err := CreateEntity(db, db.stmts.CreateACMEIssuanceAttempt, row)
	return err
}

// ListACMEIssuanceAttempts returns every attempt currently recorded as in
// flight. Attempts are deleted as they finish, so a non-empty result during
// steady state is either a live attempt or an orphan left by a dead node.
func (db *DatabaseRepository) ListACMEIssuanceAttempts() ([]ACMEIssuanceAttempt, error) {
	return ListEntities[ACMEIssuanceAttempt](db, db.stmts.ListACMEIssuanceAttempts)
}

// DeleteACMEIssuanceAttempt clears the in-flight record for csrID. It is called
// once an attempt finishes, whether it succeeded or failed, and is a no-op if
// no attempt is recorded so that callers can defer it unconditionally.
func (db *DatabaseRepository) DeleteACMEIssuanceAttempt(csrID int64) error {
	row := ACMEIssuanceAttempt{CSRID: csrID}
	return DeleteEntity(db, db.stmts.DeleteACMEIssuanceAttempt, row)
}

// FailCertificateRequest moves a request to the terminal 'Failed' status.
//
// Only a request that is still 'Outstanding' is failed. A request that reached
// 'Active', 'Rejected' or 'Revoked' has a settled outcome, and overwriting it
// would discard a real result — which matters because this is called from
// crash recovery, where an attempt may have completed just before the record of
// it was cleaned up.
func (db *DatabaseRepository) FailCertificateRequest(csrID int64) error {
	csr, err := db.GetCertificateRequest(ByCSRID(csrID))
	if err != nil {
		return err
	}
	if csr.Status != "Outstanding" {
		return nil
	}

	filter := ByCSRID(csrID)
	row := filter.AsCertificateRequest()
	row.CertificateID = 0
	row.Status = StatusFailed

	return UpdateEntity(db, db.stmts.UpdateCertificateRequest, row)
}
