package db_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestCSRsEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer db.Close()

	err = db.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.CreateCertificateRequest(StrawberryCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	res, err := db.ListCertificateRequests()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 3 {
		t.Fatalf("One or more CSRs weren't found in DB")
	}
	retrievedCSR, err := db.GetCertificateRequestByCSR(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != AppleCSR {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}
	if err = db.DeleteCertificateRequestByCSR(AppleCSR); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.ListCertificateRequests()
	if len(res) != 2 {
		t.Fatalf("CSR's weren't deleted from the DB properly")
	}
}

func TestCreateFails(t *testing.T) {
	db, _ := db.NewDatabase(":memory:")
	defer db.Close()

	InvalidCSR := strings.ReplaceAll(AppleCSR, "M", "i")
	if err := db.CreateCertificateRequest(InvalidCSR); err == nil {
		t.Fatalf("Expected error due to invalid CSR")
	}

	db.CreateCertificateRequest(AppleCSR) //nolint:errcheck
	if err := db.CreateCertificateRequest(AppleCSR); err == nil {
		t.Fatalf("Expected error due to duplicate CSR")
	}
}

func TestRetrieve(t *testing.T) {
	db, _ := db.NewDatabase(":memory:") //nolint:errcheck
	defer db.Close()

	db.CreateCertificateRequest(AppleCSR) //nolint:errcheck
	if _, err := db.GetCertificateRequestByCSR("this is definitely not an id"); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
	if _, err := db.GetCertificateRequestByID(-1); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}
}
