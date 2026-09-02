package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var EmbedMigrations embed.FS

// Apply runs pending goose migrations against the opened dqlite database.
// Each SQL statement is executed separately (no StatementBegin blocks) so it
// works with dqlite's single-statement Exec.
func Apply(ctx context.Context, sqldb *sql.DB) error {
	provider, err := goose.NewProvider(goose.DialectSQLite3, sqldb, EmbedMigrations, goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	return nil
}
