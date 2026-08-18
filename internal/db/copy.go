package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// schemaObject is one entry of a SQLite database's schema.
type schemaObject struct {
	kind string
	name string
	sql  string
}

// CopyDatabase reproduces the SQLite database at sourcePath inside dest, which
// must be empty.
//
// Restoring a clustered deployment cannot be a file substitution the way the
// single-file path is: dqlite keeps the authoritative copy of the database in
// its Raft log, not in a file a running node could have swapped underneath it.
// So a restore replays the backup's schema and rows into a freshly bootstrapped
// cluster instead, which leaves the new cluster holding the backup's dataset
// through the same write path as any other change.
func CopyDatabase(ctx context.Context, sourcePath string, dest *sql.DB) error {
	source, err := sql.Open("sqlite", localDSN(sourcePath))
	if err != nil {
		return fmt.Errorf("failed to open the backup database: %w", err)
	}
	defer source.Close() //nolint:errcheck

	if err := source.PingContext(ctx); err != nil {
		return fmt.Errorf("the backup is not a valid database: %w", err)
	}

	objects, err := readSchema(ctx, source)
	if err != nil {
		return err
	}

	empty, err := isEmptyDatabase(ctx, dest)
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("the destination database already holds data")
	}

	// One transaction for the whole restore: a failure part way through leaves
	// the new cluster empty and retryable, rather than holding a fraction of the
	// backup that looks like a successful restore.
	tx, err := dest.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start the restore: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Tables come first so rows have somewhere to go, and everything derived
	// from those rows — indexes, triggers, views — is created afterwards, so it
	// is built once from the finished data rather than maintained row by row.
	for _, object := range objects {
		if object.kind == "table" {
			if _, err := tx.ExecContext(ctx, object.sql); err != nil {
				return fmt.Errorf("failed to recreate table %q: %w", object.name, err)
			}
		}
	}

	for _, object := range objects {
		if object.kind != "table" {
			continue
		}
		if err := copyTable(ctx, source, tx, object.name); err != nil {
			return err
		}
	}

	for _, object := range objects {
		if object.kind != "table" {
			if _, err := tx.ExecContext(ctx, object.sql); err != nil {
				return fmt.Errorf("failed to recreate %s %q: %w", object.kind, object.name, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to complete the restore: %w", err)
	}

	return nil
}

// readSchema returns every schema object of a database, in creation order.
//
// Creation order matters: SQLite records tables in the order they were created,
// which is the order in which their foreign keys resolve.
func readSchema(ctx context.Context, source *sql.DB) ([]schemaObject, error) {
	rows, err := source.QueryContext(ctx, `
		SELECT type, name, sql FROM sqlite_master
		WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
		ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("failed to read the backup schema: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var objects []schemaObject
	for rows.Next() {
		var object schemaObject
		if err := rows.Scan(&object.kind, &object.name, &object.sql); err != nil {
			return nil, fmt.Errorf("failed to read the backup schema: %w", err)
		}
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read the backup schema: %w", err)
	}
	if len(objects) == 0 {
		return nil, errors.New("the backup holds no tables")
	}

	return objects, nil
}

// isEmptyDatabase reports whether a database has a schema of its own yet.
func isEmptyDatabase(ctx context.Context, database *sql.DB) (bool, error) {
	var count int
	err := database.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to inspect the destination database: %w", err)
	}

	return count == 0, nil
}

// copyTable copies every row of one table from source to dest.
func copyTable(ctx context.Context, source *sql.DB, dest *sql.Tx, table string) error {
	rows, err := source.QueryContext(ctx, "SELECT * FROM "+quoteIdentifier(table))
	if err != nil {
		return fmt.Errorf("failed to read table %q from the backup: %w", table, err)
	}
	defer rows.Close() //nolint:errcheck

	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("failed to read the columns of table %q: %w", table, err)
	}
	if len(columns) == 0 {
		return nil
	}

	quoted := make([]string, 0, len(columns))
	placeholders := make([]string, 0, len(columns))
	for _, column := range columns {
		quoted = append(quoted, quoteIdentifier(column))
		placeholders = append(placeholders, "?")
	}
	insert := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		quoteIdentifier(table), strings.Join(quoted, ", "), strings.Join(placeholders, ", "))

	statement, err := dest.PrepareContext(ctx, insert)
	if err != nil {
		return fmt.Errorf("failed to prepare the insert for table %q: %w", table, err)
	}
	defer statement.Close() //nolint:errcheck

	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(pointers...); err != nil {
			return fmt.Errorf("failed to read a row of table %q: %w", table, err)
		}
		if _, err := statement.ExecContext(ctx, values...); err != nil {
			return fmt.Errorf("failed to restore a row of table %q: %w", table, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to read table %q from the backup: %w", table, err)
	}

	return nil
}

// quoteIdentifier renders a table or column name as a SQLite identifier.
//
// The names being quoted come out of the schema of an operator-supplied backup
// file rather than from this codebase, so they are untrusted input that ends up
// in a statement; quoting them is what keeps a crafted backup from smuggling SQL
// through a table name.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
