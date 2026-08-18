package db_test

import (
	"errors"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCreateClusterJoinTokenRejectsInvalidInput(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	tests := []struct {
		name      string
		tokenHash string
		role      db.ClusterRole
		expiresAt time.Time
	}{
		{"empty hash", "", db.ClusterRoleStandBy, now.Add(time.Hour)},
		{"unknown role", "hash", db.ClusterRole("leader"), now.Add(time.Hour)},
		{"expiry in the past", "hash", db.ClusterRoleStandBy, now.Add(-time.Hour)},
		{"expiry equal to creation", "hash", db.ClusterRoleStandBy, now},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := database.CreateClusterJoinToken(tt.tokenHash, tt.role, now, tt.expiresAt)
			if !errors.Is(err, db.ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestRedeemClusterJoinTokenSucceedsOnce(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterJoinToken("hash", db.ClusterRoleVoter, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("couldn't create join token: %s", err)
	}

	role, err := database.RedeemClusterJoinToken("hash", now)
	if err != nil {
		t.Fatalf("couldn't redeem join token: %s", err)
	}
	if role != db.ClusterRoleVoter {
		t.Errorf("got role %q, want %q", role, db.ClusterRoleVoter)
	}

	// A join token authorizes exactly one join; the second attempt must fail
	// even though the row is still there.
	if _, err := database.RedeemClusterJoinToken("hash", now); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected the second redemption to fail with ErrNotFound, got %v", err)
	}
}

func TestRedeemClusterJoinTokenRejectsUnusableTokens(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterJoinToken("expired", db.ClusterRoleStandBy, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("couldn't create join token: %s", err)
	}

	tests := []struct {
		name      string
		tokenHash string
	}{
		{"unknown token", "never-issued"},
		{"expired token", "expired"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := database.RedeemClusterJoinToken(tt.tokenHash, now); !errors.Is(err, db.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})
	}
}

func TestCreateClusterJoinTokenRejectsDuplicateHash(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterJoinToken("hash", db.ClusterRoleStandBy, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("couldn't create join token: %s", err)
	}
	if _, err := database.CreateClusterJoinToken("hash", db.ClusterRoleStandBy, now, now.Add(time.Hour)); !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestDeleteExpiredClusterJoinTokens(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterJoinToken("expired", db.ClusterRoleStandBy, now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatalf("couldn't create join token: %s", err)
	}
	if _, err := database.CreateClusterJoinToken("live", db.ClusterRoleStandBy, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("couldn't create join token: %s", err)
	}

	if err := database.DeleteExpiredClusterJoinTokens(now); err != nil {
		t.Fatalf("couldn't delete expired join tokens: %s", err)
	}

	tokens, err := database.ListClusterJoinTokens()
	if err != nil {
		t.Fatalf("couldn't list join tokens: %s", err)
	}
	if len(tokens) != 1 || tokens[0].TokenHash != "live" {
		t.Fatalf("got %d token(s) %v, want only the live one", len(tokens), tokens)
	}

	// Deleting again must not report a missing row as an error.
	if err := database.DeleteExpiredClusterJoinTokens(now); err != nil {
		t.Fatalf("expected deleting nothing to succeed, got %s", err)
	}
}

func TestClusterMembersEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterMember("1234567890123456789", "node-1", "10.0.0.1:9000", now); err != nil {
		t.Fatalf("couldn't create cluster member: %s", err)
	}

	member, err := database.GetClusterMember("1234567890123456789")
	if err != nil {
		t.Fatalf("couldn't get cluster member: %s", err)
	}
	if member.Name != "node-1" || member.Address != "10.0.0.1:9000" {
		t.Errorf("got %+v, want node-1 at 10.0.0.1:9000", member)
	}

	byName, err := database.GetClusterMemberByName("node-1")
	if err != nil {
		t.Fatalf("couldn't get cluster member by name: %s", err)
	}
	if byName.NodeID != "1234567890123456789" {
		t.Errorf("got node ID %q, want 1234567890123456789", byName.NodeID)
	}

	if err := database.DeleteClusterMember("1234567890123456789"); err != nil {
		t.Fatalf("couldn't delete cluster member: %s", err)
	}
	if _, err := database.GetClusterMember("1234567890123456789"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

// dqlite node IDs are uint64 and routinely exceed what an int64 column could
// hold, which is why the column is TEXT.
func TestClusterMemberNodeIDSurvivesUint64Range(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	const maxUint64 = "18446744073709551615"

	if _, err := database.CreateClusterMember(maxUint64, "node-max", "10.0.0.9:9000", time.Now().UTC()); err != nil {
		t.Fatalf("couldn't create cluster member: %s", err)
	}

	member, err := database.GetClusterMember(maxUint64)
	if err != nil {
		t.Fatalf("couldn't get cluster member: %s", err)
	}
	if member.NodeID != maxUint64 {
		t.Errorf("got node ID %q, want %q", member.NodeID, maxUint64)
	}
}

func TestCreateClusterMemberRejectsDuplicates(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	if _, err := database.CreateClusterMember("1", "node-1", "10.0.0.1:9000", now); err != nil {
		t.Fatalf("couldn't create cluster member: %s", err)
	}

	tests := []struct {
		name    string
		nodeID  string
		member  string
		address string
	}{
		{"duplicate node id", "1", "node-2", "10.0.0.2:9000"},
		{"duplicate name", "2", "node-1", "10.0.0.2:9000"},
		{"duplicate address", "2", "node-2", "10.0.0.1:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := database.CreateClusterMember(tt.nodeID, tt.member, tt.address, now); !errors.Is(err, db.ErrAlreadyExists) {
				t.Fatalf("expected ErrAlreadyExists, got %v", err)
			}
		})
	}
}

func TestCreateClusterMemberRejectsEmptyFields(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	now := time.Now().UTC()

	tests := []struct {
		name    string
		nodeID  string
		member  string
		address string
	}{
		{"empty node id", "", "node-1", "10.0.0.1:9000"},
		{"empty name", "1", "", "10.0.0.1:9000"},
		{"empty address", "1", "node-1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := database.CreateClusterMember(tt.nodeID, tt.member, tt.address, now); !errors.Is(err, db.ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}
