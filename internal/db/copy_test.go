package db_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// openTestDB opens a SQLite database file for a test.
func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()

	connection, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("failed to open %q: %v", path, err)
	}
	t.Cleanup(func() { connection.Close() }) //nolint:errcheck

	return connection
}

func execAll(t *testing.T, database *sql.DB, statements ...string) {
	t.Helper()

	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("failed to execute %q: %v", statement, err)
		}
	}
}

// backupDatabase builds a source database standing in for a dumped one: two
// tables tied together by a foreign key, an index, and a table whose name needs
// quoting.
func backupDatabase(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "notary")
	source := openTestDB(t, path)
	execAll(t, source,
		`CREATE TABLE authorities (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`CREATE TABLE certificates (id INTEGER PRIMARY KEY, authority_id INTEGER REFERENCES authorities(id), pem BLOB)`,
		`CREATE INDEX certificates_by_authority ON certificates (authority_id)`,
		`CREATE TABLE "odd ""name" (value TEXT)`,
		`INSERT INTO authorities (id, name) VALUES (1, 'root'), (2, 'intermediate')`,
		`INSERT INTO certificates (id, authority_id, pem) VALUES (1, 1, x'0102'), (2, 2, NULL)`,
		`INSERT INTO "odd ""name" (value) VALUES ('kept')`,
	)
	if err := source.Close(); err != nil {
		t.Fatalf("failed to close the source database: %v", err)
	}

	return path
}

func TestCopyDatabaseReproducesTheBackup(t *testing.T) {
	sourcePath := backupDatabase(t)
	dest := openTestDB(t, filepath.Join(t.TempDir(), "restored"))

	if err := db.CopyDatabase(context.Background(), sourcePath, dest); err != nil {
		t.Fatalf("failed to copy database: %v", err)
	}

	var authorities int
	if err := dest.QueryRow(`SELECT count(*) FROM authorities`).Scan(&authorities); err != nil {
		t.Fatalf("failed to count authorities: %v", err)
	}
	if authorities != 2 {
		t.Errorf("expected 2 authorities, got %d", authorities)
	}

	var pem []byte
	var authorityID sql.NullInt64
	if err := dest.QueryRow(`SELECT authority_id, pem FROM certificates WHERE id = 1`).Scan(&authorityID, &pem); err != nil {
		t.Fatalf("failed to read a restored certificate: %v", err)
	}
	if authorityID.Int64 != 1 || string(pem) != "\x01\x02" {
		t.Errorf("restored certificate does not match the backup: %d, %x", authorityID.Int64, pem)
	}

	// A NULL has to survive as a NULL: restoring it as an empty value would
	// quietly change what the data means.
	var nullable []byte
	if err := dest.QueryRow(`SELECT pem FROM certificates WHERE id = 2`).Scan(&nullable); err != nil {
		t.Fatalf("failed to read the second restored certificate: %v", err)
	}
	if nullable != nil {
		t.Errorf("expected a NULL certificate, got %x", nullable)
	}

	var index string
	if err := dest.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'certificates_by_authority'`).Scan(&index); err != nil {
		t.Errorf("expected the index to be restored: %v", err)
	}

	var odd string
	if err := dest.QueryRow(`SELECT value FROM "odd ""name"`).Scan(&odd); err != nil {
		t.Fatalf("failed to read the awkwardly named table: %v", err)
	}
	if odd != "kept" {
		t.Errorf("expected 'kept', got %q", odd)
	}
}

func TestCopyDatabaseRefusesANonEmptyDestination(t *testing.T) {
	sourcePath := backupDatabase(t)
	dest := openTestDB(t, filepath.Join(t.TempDir(), "restored"))
	execAll(t, dest, `CREATE TABLE authorities (id INTEGER PRIMARY KEY)`)

	if err := db.CopyDatabase(context.Background(), sourcePath, dest); err == nil {
		t.Fatal("expected a destination that already holds data to be refused")
	}
}

func TestCopyDatabaseRejectsAFileThatIsNotADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notary")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatalf("failed to write the file: %v", err)
	}
	dest := openTestDB(t, filepath.Join(t.TempDir(), "restored"))

	if err := db.CopyDatabase(context.Background(), path, dest); err == nil {
		t.Fatal("expected a file that is not a database to be rejected")
	}
}

// TestCopyDatabaseCarriesNotarysOwnSchema restores a real Notary database rather
// than a hand-written one, so the copy is exercised against the schema the
// migrations actually produce — including the migration bookkeeping, which the
// restored cluster needs in order to know what version it is on.
func TestCopyDatabaseCarriesNotarysOwnSchema(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "notary")
	logger := zap.NewNop()

	source, err := db.NewDatabase(&db.DatabaseOpts{DatabasePath: sourcePath, Logger: logger})
	if err != nil {
		t.Fatalf("failed to create the source database: %v", err)
	}
	if _, err := source.CreateUser("admin@canonical.com", "pw123", db.RoleAdmin); err != nil {
		t.Fatalf("failed to create a user: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("failed to close the source database: %v", err)
	}

	destPath := filepath.Join(t.TempDir(), "restored")
	dest := openTestDB(t, destPath)
	if err := db.CopyDatabase(context.Background(), sourcePath, dest); err != nil {
		t.Fatalf("failed to copy database: %v", err)
	}

	restored, err := db.NewDatabaseFromConn(dest, &db.DatabaseOpts{DatabasePath: destPath, Logger: logger})
	if err != nil {
		t.Fatalf("failed to open the restored database: %v", err)
	}

	users, err := restored.ListUsers()
	if err != nil {
		t.Fatalf("failed to list restored users: %v", err)
	}
	if len(users) != 1 || users[0].Email != "admin@canonical.com" {
		t.Fatalf("expected the backed up user to be restored, got %+v", users)
	}
}
