package cluster_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// Leadership can move after RedeemJoinToken has already spent the ticket. The
// join must either finish or say plainly that the token is gone, never leave
// the operator retrying a ticket that can no longer work.
func TestJoinSurvivesLeadershipChangeAfterRedeem(t *testing.T) {
	httpsCert, _ := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr3, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}

	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(), Address: addr1, Name: "node1",
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8443", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	stubJoinExchange(t, db1, addr1)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	token2, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token node2: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(), Address: addr2, Name: "node2", JoinToken: token2,
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8444", Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	token3, err := db1.IssueJoinToken(ctx, "node3")
	if err != nil {
		t.Fatalf("token node3: %v", err)
	}

	// Hand leadership away in the window between spending the ticket and joining.
	cluster.ExchangeJoinToken = func(ctx context.Context, raw string) (cluster.JoinMaterial, error) {
		tok, err := cluster.DecodeJoinToken(raw)
		if err != nil {
			return cluster.JoinMaterial{}, err
		}
		material, err := cluster.RedeemJoinToken(ctx, db1.Conn.PlainDB(), tok, db1.TLSCert, db1.TLSKey)
		if err != nil {
			return cluster.JoinMaterial{}, err
		}
		if err := db1.Node.Handover(ctx); err != nil {
			t.Logf("handover during redeem: %v", err)
		}
		material.Join = []string{addr1, addr2}
		return material, nil
	}

	db3, joinErr := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(), Address: addr3, Name: "node3", JoinToken: token3,
		HTTPSCert: httpsCert, APIAddress: "127.0.0.1:8445", Logger: zap.NewNop(),
	})
	if joinErr == nil {
		defer db3.Close() //nolint:errcheck
		members, err := db3.ListClusterMembers(ctx)
		if err != nil {
			t.Fatalf("list from node3: %v", err)
		}
		if len(members) != 3 {
			t.Fatalf("got %d members, want 3", len(members))
		}
		return
	}

	// If it could not finish, the operator must be told the ticket is spent.
	if !strings.Contains(joinErr.Error(), cluster.JoinIncompleteMessage) {
		t.Fatalf("join failed without the incomplete-join hint: %v", joinErr)
	}
	if _, err := cluster.DecodeJoinToken(token3); err != nil {
		t.Fatalf("token should still decode: %v", err)
	}
}
