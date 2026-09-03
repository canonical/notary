package cluster_test

import (
	"context"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
)

func TestStartOpenAndResume(t *testing.T) {
	dir := t.TempDir()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatalf("free address: %v", err)
	}

	node, err := cluster.Start(cluster.Options{Dir: dir, Address: addr})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := node.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("close node: %v", err)
	}

	if !cluster.HasState(dir) {
		t.Fatal("expected dqlite identity after bootstrap")
	}

	resumed, err := cluster.Start(cluster.Options{Dir: dir, Address: addr})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer resumed.Close() //nolint:errcheck
	db2, err := resumed.Open(ctx)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close() //nolint:errcheck
	if _, err := db2.ExecContext(ctx, `INSERT INTO t (id) VALUES (1)`); err != nil {
		t.Fatalf("insert after resume: %v", err)
	}
}
