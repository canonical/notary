package db_test

import (
	"log"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestConnect(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
	db.Close()
}

func Example() {
	database, err := db.NewDatabase("./notary.db")
	if err != nil {
		log.Fatalln(err)
	}
	csrID, err := database.CreateCertificateRequest(BananaCSR)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRID(csrID), BananaCert)
	if err != nil {
		log.Fatalln(err)
	}
	err = database.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
