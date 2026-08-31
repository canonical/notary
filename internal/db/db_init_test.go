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
