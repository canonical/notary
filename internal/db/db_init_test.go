package db_test

import (
	"log"
	"testing"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

func TestConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatalf("Couldn't get free address: %s", err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("Can't connect to dqlite: %s", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Can't close database: %s", err)
	}
}

func TestMigrationsApplied(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatalf("Couldn't get free address: %s", err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("Can't connect to dqlite: %s", err)
	}
	defer database.Close() //nolint:errcheck

	var version int
	err = database.Conn.PlainDB().QueryRow(`SELECT MAX(version_id) FROM goose_db_version`).Scan(&version)
	if err != nil {
		t.Fatalf("read goose version: %s", err)
	}
	if version != 4 {
		t.Fatalf("got goose version %d, want 4", version)
	}
}

func Example() {
	logger, _ := zap.NewDevelopment()
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: "./notary.dqlite",
		Address:      "127.0.0.1:9000",
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
