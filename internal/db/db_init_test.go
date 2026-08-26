package db_test

import (
	"database/sql"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/db/migrations"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

func TestConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	tempDir := t.TempDir()

	sqlConnection, err := sql.Open("sqlite", filepath.Join(tempDir, "db.sqlite"))
	if err != nil {
		t.Fatalf("Couldn't create temporary database: %s", err)
	}
	goose.SetBaseFS(migrations.EmbedMigrations)
	err = goose.SetDialect("sqlite")
	if err != nil {
		t.Fatalf("Couldn't set goose dialect: %s", err)
	}
	err = goose.Up(sqlConnection, ".", goose.WithNoColor(true))
	if err != nil {
		t.Fatalf("Couldn't apply database migrations: %s", err)
	}
	db, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: filepath.Join(tempDir, "db.sqlite"),
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
	err = db.Close()
	if err != nil {
		t.Fatalf("Can't close database: %s", err)
	}
}

func TestConnectRejectsANonCurrentSchema(t *testing.T) {
	logger := zap.NewNop()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	sqlConnection, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Couldn't create temporary database: %s", err)
	}
	if err := goose.SetDialect("sqlite"); err != nil {
		t.Fatalf("Couldn't set goose dialect: %s", err)
	}
	if _, err := goose.EnsureDBVersion(sqlConnection); err != nil {
		t.Fatalf("Couldn't initialize schema metadata: %s", err)
	}
	if _, err := sqlConnection.Exec("UPDATE goose_db_version SET version_id = 2 WHERE id = (SELECT max(id) FROM goose_db_version)"); err != nil {
		t.Fatalf("Couldn't set non-current schema version: %s", err)
	}
	if err := sqlConnection.Close(); err != nil {
		t.Fatalf("Couldn't close temporary database: %s", err)
	}

	_, err = db.NewDatabase(&db.DatabaseOpts{DatabasePath: path, Logger: logger})
	if err == nil || !strings.Contains(err.Error(), "start with an empty database") {
		t.Fatalf("got %v, want a fresh-database error", err)
	}
}

func Example() {
	logger, _ := zap.NewDevelopment()
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: "./notary.db",
		Logger:       logger,
	})
	if err != nil {
		log.Fatalln(err)
	}
	csrID, err := database.CreateCertificateRequest("----- CERTIFICATE REQUEST -----...", "user@example.com")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRID(csrID), "----- CERTIFICATE -----...")
	if err != nil {
		log.Fatalln(err)
	}
	err = database.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
