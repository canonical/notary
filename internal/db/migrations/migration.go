package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var EmbedMigrations embed.FS

const migrationLockStealAfter = 2 * time.Minute

// tableLocker serializes goose Up across cluster members. Goose locking is off
// by default; without it, simultaneous start races ALTER on goose_db_version.
//
// Rolling upgrades: only additive migrations (new tables, ADD COLUMN with a
// default). Older members keep serving; they never SELECT new columns. Do not
// rename or drop columns in a version that mixed binaries will run.
type tableLocker struct{}

func (tableLocker) Lock(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS goose_migration_lock (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			locked_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create migration lock table: %w", err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		now := time.Now().UTC()
		stale := now.Add(-migrationLockStealAfter).Format(time.RFC3339)
		res, err := db.ExecContext(ctx, `
			INSERT INTO goose_migration_lock (id, locked_at) VALUES (1, ?)
			ON CONFLICT(id) DO UPDATE SET locked_at = excluded.locked_at
			WHERE goose_migration_lock.locked_at < ?
		`, now.Format(time.RFC3339), stale)
		if err == nil {
			if n, nerr := res.RowsAffected(); nerr == nil && n == 1 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("wait for schema migration lock: %w", err)
			}
			return fmt.Errorf("wait for schema migration lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (tableLocker) Unlock(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `DELETE FROM goose_migration_lock WHERE id = 1`)
	return err
}

// Apply runs pending goose migrations against the opened dqlite database.
// Each SQL statement is executed separately (no StatementBegin blocks) so it
// works with dqlite's single-statement Exec.
func Apply(ctx context.Context, sqldb *sql.DB) error {
	provider, err := goose.NewProvider(
		goose.DialectSQLite3,
		sqldb,
		EmbedMigrations,
		goose.WithLogger(goose.NopLogger()),
		goose.WithLocker(tableLocker{}),
	)
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	return nil
}
