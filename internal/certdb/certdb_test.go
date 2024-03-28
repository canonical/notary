package certdb_test

import (
	"testing"

	"github.com/canonical/gocert/internal/certdb"
)

func TestConnection(t *testing.T) {
	db := new(certdb.CertificateRequests)
	defer db.Disconnect()
	if err := db.Connect(":memory:", "CertificateReqs"); err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
}

func TestDatabase(t *testing.T) {
	db := new(certdb.CertificateRequests)
	defer db.Disconnect()
	db.Connect(":memory:", "CertificateRequests")

	if _, err := db.Create(&ValidCSR1); err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if _, err := db.Create(&ValidCSR2); err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if _, err := db.Create(&ValidCSR3); err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.RetrieveAll()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 3 {
		t.Fatalf("One or more CSR's weren't found in DB")
	}
	retrievedCSR, err := db.Retrieve(&ValidCSR1)
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != ValidCSR1 {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}

	if err = db.Delete(&ValidCSR1); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.RetrieveAll()
	if len(res) != 2 {
		t.Fatalf("CSR's weren't deleted from the DB properly")
	}

	_, err = db.Update(&ValidCSR2, &ValidCert2)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSR, _ = db.Retrieve(&ValidCSR2)
	if *retrievedCSR.Certificate != ValidCert2 {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given: Retrieved: %s\nGiven: %s", *retrievedCSR.Certificate, ValidCert2)
	}
}
