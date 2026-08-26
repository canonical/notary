package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CreateClusterJoinToken stores the hash of a newly issued join token. The token
// itself is never persisted; see cluster.GenerateJoinToken.
func (db *DatabaseRepository) CreateClusterJoinToken(tokenHash string, createdAt, expiresAt time.Time) (int64, error) {
	if tokenHash == "" {
		return 0, fmt.Errorf("failed to create cluster join token: %w: token hash is empty", ErrInvalidInput)
	}
	if !expiresAt.After(createdAt) {
		return 0, fmt.Errorf("failed to create cluster join token: %w: expiry is not in the future", ErrInvalidInput)
	}

	row := ClusterJoinToken{
		TokenHash: tokenHash,
		CreatedAt: createdAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}
	return CreateEntity[ClusterJoinToken](db, db.stmts.CreateClusterJoinToken, row)
}

// VerifyClusterJoinToken reports whether a join token is currently redeemable,
// without consuming it.
//
// It exists so the join handler can reject a request it was never going to be
// able to satisfy — a malformed CSR, a schema version it does not share — before
// spending the operator's single-use token on it.
func (db *DatabaseRepository) VerifyClusterJoinToken(tokenHash string, now time.Time) error {
	var unused int
	err := db.Conn.PlainDB().QueryRow(
		"SELECT 1 FROM cluster_join_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
		tokenHash, now.Unix(),
	).Scan(&unused)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("failed to verify cluster join token: %w", ErrNotFound)
	case err != nil:
		return fmt.Errorf("failed to verify cluster join token: %w: %w", ErrInternal, err)
	}

	return nil
}

// RedeemClusterJoinToken consumes a join token.
//
// Redemption is a single conditional UPDATE rather than a read followed by a
// write: a token is valid exactly once, and two nodes may present the same token
// to two different members at the same time. Only the update that observes
// used_at still NULL wins, so the loser is rejected as already used.
func (db *DatabaseRepository) RedeemClusterJoinToken(tokenHash string, now time.Time) error {
	result, err := db.Conn.PlainDB().Exec(
		"UPDATE cluster_join_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
		now.Unix(), tokenHash, now.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to redeem cluster join token: %w: %w", ErrInternal, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to redeem cluster join token: %w: %w", ErrInternal, err)
	}
	if affected == 0 {
		// The token is unknown, already used, or expired. These are deliberately
		// indistinguishable to the caller so a failed join reveals nothing about
		// which tokens exist.
		return fmt.Errorf("failed to redeem cluster join token: %w", ErrNotFound)
	}

	return nil
}

// ListClusterJoinTokens returns every issued join token, used and unused alike.
// Only hashes are returned; the tokens themselves are unrecoverable.
func (db *DatabaseRepository) ListClusterJoinTokens() ([]ClusterJoinToken, error) {
	return ListEntities[ClusterJoinToken](db, db.stmts.ListClusterJoinTokens)
}

// DeleteClusterJoinToken removes a join token by its row ID.
func (db *DatabaseRepository) DeleteClusterJoinToken(id int64) error {
	row := ClusterJoinToken{ID: id}
	return DeleteEntity[ClusterJoinToken](db, db.stmts.DeleteClusterJoinToken, row)
}

// DeleteExpiredClusterJoinTokens removes every token that expired before now. An
// expired token is already unusable; this only keeps the table from growing.
func (db *DatabaseRepository) DeleteExpiredClusterJoinTokens(now time.Time) error {
	row := ClusterJoinToken{ExpiresAt: now.Unix()}
	if err := DeleteEntity[ClusterJoinToken](db, db.stmts.DeleteExpiredJoinTokens, row); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// OfflineThreshold is how long a member may go without a heartbeat before its
// peers report it offline. It matches LXD's `cluster.offline_threshold` default.
const OfflineThreshold = 20 * time.Second

// Online reports whether a member's last heartbeat is recent enough for it to
// still count as alive.
func (m ClusterMember) Online(now time.Time) bool {
	if m.Heartbeat == nil {
		return false
	}
	return now.Sub(time.Unix(*m.Heartbeat, 0)) <= OfflineThreshold
}

// CreateClusterMember records the operator-assigned name for a node that just
// joined the cluster.
func (db *DatabaseRepository) CreateClusterMember(nodeID, name, address string, joinedAt time.Time) (int64, error) {
	if nodeID == "" || name == "" || address == "" {
		return 0, fmt.Errorf("failed to create cluster member: %w: node ID, name and address are all required", ErrInvalidInput)
	}

	row := ClusterMember{
		NodeID:   nodeID,
		Name:     name,
		Address:  address,
		JoinedAt: joinedAt.Unix(),
	}
	return CreateEntity[ClusterMember](db, db.stmts.CreateClusterMember, row)
}

// ListClusterMembers returns the name records for all known members.
func (db *DatabaseRepository) ListClusterMembers() ([]ClusterMember, error) {
	return ListEntities[ClusterMember](db, db.stmts.ListClusterMembers)
}

// RecordClusterMemberHeartbeat records that a member is alive, along with its
// own view of its seal state.
//
// Only a member ever writes its own row. The write is replicated, so every
// other member learns of it without reaching this node's API, and the write
// succeeding is itself proof this node can still reach the Raft leader.
func (db *DatabaseRepository) RecordClusterMemberHeartbeat(nodeID, address string, sealed bool, at time.Time) error {
	if nodeID == "" {
		return fmt.Errorf("failed to record cluster member heartbeat: %w: node ID is empty", ErrInvalidInput)
	}
	if address == "" {
		return fmt.Errorf("failed to record cluster member heartbeat: %w: address is empty", ErrInvalidInput)
	}

	beat := at.Unix()
	row := ClusterMember{
		NodeID:  nodeID,
		// Only used if no row exists yet, which is the repair case: the member is
		// in the cluster but its bookkeeping was never written, and without this
		// it would report as offline for as long as it ran.
		Name:      address,
		Address:   address,
		JoinedAt:  beat,
		Heartbeat: &beat,
		Sealed:    sealed,
	}
	_, err := CreateEntity[ClusterMember](db, db.stmts.HeartbeatClusterMember, row)
	return err
}

// GetClusterMember looks a member up by its dqlite node ID.
func (db *DatabaseRepository) GetClusterMember(nodeID string) (*ClusterMember, error) {
	row := ClusterMember{NodeID: nodeID}
	return GetOneEntity[ClusterMember](db, db.stmts.GetClusterMember, row)
}

// GetClusterMemberByName looks a member up by its operator-assigned name, which
// is how the CLI and API address members.
func (db *DatabaseRepository) GetClusterMemberByName(name string) (*ClusterMember, error) {
	row := ClusterMember{Name: name}
	return GetOneEntity[ClusterMember](db, db.stmts.GetClusterMemberByName, row)
}

// DeleteClusterMember drops the name record for a removed member.
func (db *DatabaseRepository) DeleteClusterMember(nodeID string) error {
	row := ClusterMember{NodeID: nodeID}
	return DeleteEntity[ClusterMember](db, db.stmts.DeleteClusterMember, row)
}
