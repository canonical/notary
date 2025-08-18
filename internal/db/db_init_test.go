package db_test

import (
	"log"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
	eb "github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
)

func TestConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	tempDir := t.TempDir()
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
