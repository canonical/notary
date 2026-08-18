package db

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CreateClusterJoinToken stores the hash of a newly issued join token. The token
// itself is never persisted; see cluster.GenerateJoinToken.
func (db *DatabaseRepository) CreateClusterJoinToken(tokenHash string, role ClusterRole, createdAt, expiresAt time.Time) (int64, error) {
	if tokenHash == "" {
		return 0, fmt.Errorf("failed to create cluster join token: %w: token hash is empty", ErrInvalidInput)
	}
	if role != ClusterRoleVoter && role != ClusterRoleStandBy {
		return 0, fmt.Errorf("failed to create cluster join token: %w: unknown role %q", ErrInvalidInput, role)
	}
	if !expiresAt.After(createdAt) {
		return 0, fmt.Errorf("failed to create cluster join token: %w: expiry is not in the future", ErrInvalidInput)
	}

	row := ClusterJoinToken{
		TokenHash: tokenHash,
		Role:      role,
		CreatedAt: createdAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}
	return CreateEntity[ClusterJoinToken](db, db.stmts.CreateClusterJoinToken, row)
}

// RedeemClusterJoinToken consumes a join token and returns the role it grants.
//
// Redemption is a single conditional UPDATE rather than a read followed by a
// write: a token is valid exactly once, and two nodes may present the same token
// to two different members at the same time. Only the update that observes
// used_at still NULL wins, so the loser is rejected as already used.
func (db *DatabaseRepository) RedeemClusterJoinToken(tokenHash string, now time.Time) (ClusterRole, error) {
	tx, err := db.Conn.PlainDB().BeginTx(context.Background(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrInternal)
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.Exec(
		"UPDATE cluster_join_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
		now.Unix(), tokenHash, now.Unix(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrInternal)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrInternal)
	}
	if affected == 0 {
		// The token is unknown, already used, or expired. These are deliberately
		// indistinguishable to the caller so a failed join reveals nothing about
		// which tokens exist.
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrNotFound)
	}

	var role string
	if err := tx.QueryRow("SELECT role FROM cluster_join_tokens WHERE token_hash = ?", tokenHash).Scan(&role); err != nil {
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrInternal)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to redeem cluster join token: %w", ErrInternal)
	}

	return ClusterRole(role), nil
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
