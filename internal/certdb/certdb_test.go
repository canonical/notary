package certdb_test

import (
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/canonical/gocert/internal/certdb"
)

func TestConnect(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateReqs")
	if err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
	db.Close()
}

func TestEndToEnd(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	if err != nil {
		t.Fatalf("Couldn't complete NewCertificateRequestsRepository: %s", err)
	}
	defer db.Close()

	id1, err := db.Create(ValidCSR1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	id2, err := db.Create(ValidCSR2)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	id3, err := db.Create(ValidCSR3)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.RetrieveAll()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 3 {
		t.Fatalf("One or more CSRs weren't found in DB")
	}
	retrievedCSR, err := db.Retrieve(strconv.FormatInt(id1, 10))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != ValidCSR1 {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}

	if _, err = db.Delete(strconv.FormatInt(id1, 10)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.RetrieveAll()
	if len(res) != 2 {
		t.Fatalf("CSR's weren't deleted from the DB properly")
	}

	_, err = db.Update(strconv.FormatInt(id2, 10), ValidCert2)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSR, _ = db.Retrieve(strconv.FormatInt(id2, 10))
	if retrievedCSR.Certificate != ValidCert2 {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSR.Certificate, ValidCert2)
	}
	_, err = db.Update(strconv.FormatInt(id2, 10), "")
	if err != nil {
		t.Fatalf("Couldn't complete Update to delete certificate: %s", err)
	}
	_, err = db.Update(strconv.FormatInt(id3, 10), "rejected")
	if err != nil {
		t.Fatalf("Couldn't complete Update to reject CSR: %s", err)
	}
	retrievedCSR, _ = db.Retrieve(strconv.FormatInt(id2, 10))
	if retrievedCSR.Certificate != "" {
		t.Fatalf("Couldn't delete certificate")
	}
}

func TestCreateFails(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateReqs") //nolint:errcheck
	defer db.Close()

	InvalidCSR := strings.ReplaceAll(ValidCSR1, "/", "+")
	if _, err := db.Create(InvalidCSR); err == nil {
		t.Fatalf("Expected error due to invalid CSR")
	}

	db.Create(ValidCSR1) //nolint:errcheck
	if _, err := db.Create(ValidCSR1); err == nil {
		t.Fatalf("Expected error due to duplicate CSR")
	}
}

func TestUpdateFails(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	defer db.Close()

	id1, _ := db.Create(ValidCSR1) //nolint:errcheck
	id2, _ := db.Create(ValidCSR2) //nolint:errcheck
	InvalidCert := strings.ReplaceAll(ValidCert2, "/", "+")
	if _, err := db.Update(strconv.FormatInt(id2, 10), InvalidCert); err == nil {
		t.Fatalf("Expected updating with invalid cert to fail")
	}
	if _, err := db.Update(strconv.FormatInt(id1, 10), ValidCert2); err == nil {
		t.Fatalf("Expected updating with mismatched cert to fail")
	}
}

func TestRetrieve(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	defer db.Close()

	db.Create(ValidCSR1) //nolint:errcheck
	if _, err := db.Retrieve("this is definitely not an id"); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}

}

func Example() {
	db, err := certdb.NewCertificateRequestsRepository("./certs.db", "CertificateReq")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = db.Create(ValidCSR2)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = db.Update(ValidCSR2, ValidCert2)
	if err != nil {
		log.Fatalln(err)
	}
	entry, err := db.Retrieve(ValidCSR2)
	if err != nil {
		log.Fatalln(err)
	}
	if entry.Certificate != ValidCert2 {
		log.Fatalln("Retrieved Certificate doesn't match Stored Certificate")
	}
	err = db.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
