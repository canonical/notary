package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// Regression: restoreJoinAfterRedeem must not reuse the handler's request
// context. JoinCluster shares one 15s deadline between the redeem and the
// member listing; when the listing fails because that deadline expired (for
// example during a leadership loss), a restore running on the same context is
// dead on arrival and the one-time token is burned even though the client was
// told to retry with it.
func TestRestoreJoinAfterRedeemWithExpiredRequestContext(t *testing.T) {
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr,
		Name:         "node1",
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("NewDatabase: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	env := &HandlerDependencies{
		AppEnvironment: &config.AppEnvironment{
			Database:     database,
			SystemLogger: zap.NewNop(),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok := cluster.JoinToken{
		ServerName: "node2",
		Secret:     strings.Repeat("a", 64),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := cluster.RestoreJoinToken(ctx, database.Conn.PlainDB(), tok); err != nil {
		t.Fatalf("plant token: %v", err)
	}
	if _, err := cluster.RedeemJoinToken(ctx, database.Conn.PlainDB(), tok, nil, nil); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	// Simulate the list failing on an already-dead request context.
	deadCtx, deadCancel := context.WithCancel(ctx)
	deadCancel()
	restoreJoinAfterRedeem(env, deadCtx, tok, errors.New("simulated list failure"))

	if _, err := cluster.RedeemJoinToken(ctx, database.Conn.PlainDB(), tok, nil, nil); err != nil {
		t.Fatalf("token was not restored after list failure: %v", err)
	}
}
