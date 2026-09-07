package cluster_test

import (
	"context"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

func TestReadLastEntryRejectsNonClusterDir(t *testing.T) {
	if _, err := cluster.ReadLastEntry(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no dqlite state")
	}
}

// A survivor of quorum loss must become writable again on its own.
func TestRecoverToSelfMakesSurvivorWritable(t *testing.T) {
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	httpsCert, _ := mustClusterCert(t)
	dir1 := t.TempDir()

	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1, Address: addr1, Name: "node1",
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8443", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("add token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(), Address: addr2, Name: "node2", JoinToken: token,
		Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}

	// Stop every member, as the recovery procedure requires.
	if err := db2.Close(); err != nil {
		t.Fatalf("stop node2: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("stop node1: %v", err)
	}

	last, err := cluster.ReadLastEntry(dir1)
	if err != nil {
		t.Fatalf("read last entry: %v", err)
	}
	if last.Term == 0 && last.Index == 0 {
		t.Fatalf("expected a non-zero raft position, got %s", last)
	}

	info, err := cluster.RecoverToSelf(dir1)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if info.Address != addr1 {
		t.Fatalf("recovered address %q, want %q", info.Address, addr1)
	}

	recovered, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1, Address: addr1, Name: "node1",
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8443", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("restart after recover: %v", err)
	}
	defer recovered.Close() //nolint:errcheck

	members, err := recovered.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list after recover: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("got %d members after recover, want 1", len(members))
	}
	if members[0].Address != addr1 || members[0].Role != "voter" {
		t.Fatalf("survivor is %+v, want %s as voter", members[0], addr1)
	}

	// The whole point of recovery: writes work again with no quorum partner.
	if _, err := recovered.IssueJoinToken(ctx, "node3"); err != nil {
		t.Fatalf("write after recover: %v", err)
	}
}

// Recovery rewrites raft membership but not cluster_members, so a rejoin under
// a name the dead cluster knew must still work.
func TestRecoveredClusterAcceptsPreviousMemberName(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	dir1 := t.TempDir()

	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1, Address: addr1, Name: "node1",
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8443", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(), Address: addr2, Name: "node2", JoinToken: token,
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8444", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("stop node2: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("stop node1: %v", err)
	}

	if _, err := cluster.RecoverToSelf(dir1); err != nil {
		t.Fatalf("recover: %v", err)
	}
	recovered, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1, Address: addr1, Name: "node1",
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8443", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("restart after recover: %v", err)
	}
	defer recovered.Close() //nolint:errcheck

	if _, err := recovered.IssueJoinToken(ctx, "node2"); err != nil {
		t.Fatalf("rejoin under a previously known name: %v", err)
	}
}
