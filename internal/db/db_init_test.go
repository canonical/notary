package db_test

import (
	"database/sql"
	"log"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/db/migrations"
	eb "github.com/canonical/notary/internal/encryption_backend"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

func TestConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	tempDir := t.TempDir()

	sqlConnection, err := sql.Open("sqlite3", filepath.Join(tempDir, "db.sqlite3"))
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
		DatabasePath: filepath.Join(tempDir, "db.sqlite3"),
		Backend:      &eb.NoEncryptionBackend{},
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

func Example() {
	logger, _ := zap.NewDevelopment()
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: "./notary.db",
		Backend:      &eb.NoEncryptionBackend{},
		Logger:       logger,
	})
	if err != nil {
		log.Fatalln(err)
	}
	csrID, err := database.CreateCertificateRequest("----- CERTIFICATE REQUEST -----...", 0)
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
