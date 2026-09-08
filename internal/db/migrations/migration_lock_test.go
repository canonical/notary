package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestTableLockerUnlockOnlyOwnOwner(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "lock.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck

	ctx := context.Background()
	a := newTableLocker()
	b := newTableLocker()
	if err := a.Lock(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE goose_migration_lock SET locked_at = '2000-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if err := b.Lock(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock(ctx, db); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := db.QueryRowContext(ctx, `SELECT owner FROM goose_migration_lock WHERE id = 1`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != b.owner {
		t.Fatalf("previous holder released the stolen lock: got %q want %q", owner, b.owner)
	}
	if err := b.Unlock(ctx, db); err != nil {
		t.Fatal(err)
	}
}
