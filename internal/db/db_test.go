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
	db, err := db.NewDatabase("./certs.db")
	if err != nil {
		log.Fatalln(err)
	}
	err = db.CreateCertificateRequest(BananaCSR)
	if err != nil {
		log.Fatalln(err)
	}
	err = db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, BananaCert)
	if err != nil {
		log.Fatalln(err)
	}
	// entry, err := db.GetCertificateRequestByCSR(BananaCSR)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// if entry.CertificateChain != BananaCert {
	// 	log.Fatalln("Retrieved Certificate doesn't match Stored Certificate")
	// }
	err = db.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
