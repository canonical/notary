package certdb_test

import (
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/canonical/gocert/internal/certdb"
	"golang.org/x/crypto/bcrypt"
)

func TestConnect(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateReqs")
	if err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
	db.Close()
}

func TestCSRsEndToEnd(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	if err != nil {
		t.Fatalf("Couldn't complete NewCertificateRequestsRepository: %s", err)
	}
	defer db.Close()

	id1, err := db.CreateCSR(ValidCSR1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	id2, err := db.CreateCSR(ValidCSR2)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	id3, err := db.CreateCSR(ValidCSR3)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.RetrieveAllCSRs()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 3 {
		t.Fatalf("One or more CSRs weren't found in DB")
	}
	retrievedCSR, err := db.RetrieveCSR(strconv.FormatInt(id1, 10))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != ValidCSR1 {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}

	if _, err = db.DeleteCSR(strconv.FormatInt(id1, 10)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.RetrieveAllCSRs()
	if len(res) != 2 {
		t.Fatalf("CSR's weren't deleted from the DB properly")
	}

	_, err = db.UpdateCSR(strconv.FormatInt(id2, 10), ValidCert2)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSR, _ = db.RetrieveCSR(strconv.FormatInt(id2, 10))
	if retrievedCSR.Certificate != ValidCert2 {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSR.Certificate, ValidCert2)
	}
	_, err = db.UpdateCSR(strconv.FormatInt(id2, 10), "")
	if err != nil {
		t.Fatalf("Couldn't complete Update to delete certificate: %s", err)
	}
	_, err = db.UpdateCSR(strconv.FormatInt(id3, 10), "rejected")
	if err != nil {
		t.Fatalf("Couldn't complete Update to reject CSR: %s", err)
	}
	retrievedCSR, _ = db.RetrieveCSR(strconv.FormatInt(id2, 10))
	if retrievedCSR.Certificate != "" {
		t.Fatalf("Couldn't delete certificate")
	}
}

func TestCreateFails(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateReqs") //nolint:errcheck
	defer db.Close()

	InvalidCSR := strings.ReplaceAll(ValidCSR1, "/", "+")
	if _, err := db.CreateCSR(InvalidCSR); err == nil {
		t.Fatalf("Expected error due to invalid CSR")
	}

	db.CreateCSR(ValidCSR1) //nolint:errcheck
	if _, err := db.CreateCSR(ValidCSR1); err == nil {
		t.Fatalf("Expected error due to duplicate CSR")
	}
}

func TestUpdateFails(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	defer db.Close()

	id1, _ := db.CreateCSR(ValidCSR1) //nolint:errcheck
	id2, _ := db.CreateCSR(ValidCSR2) //nolint:errcheck
	InvalidCert := strings.ReplaceAll(ValidCert2, "/", "+")
	if _, err := db.UpdateCSR(strconv.FormatInt(id2, 10), InvalidCert); err == nil {
		t.Fatalf("Expected updating with invalid cert to fail")
	}
	if _, err := db.UpdateCSR(strconv.FormatInt(id1, 10), ValidCert2); err == nil {
		t.Fatalf("Expected updating with mismatched cert to fail")
	}
}

func TestRetrieve(t *testing.T) {
	db, _ := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	defer db.Close()

	db.CreateCSR(ValidCSR1) //nolint:errcheck
	if _, err := db.RetrieveCSR("this is definitely not an id"); err == nil {
		t.Fatalf("Expected failure looking for nonexistent CSR")
	}

}

func TestUsersEndToEnd(t *testing.T) {
	db, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests") //nolint:errcheck
	if err != nil {
		t.Fatalf("Couldn't complete NewCertificateRequestsRepository: %s", err)
	}
	defer db.Close()

	id1, err := db.CreateUser("admin", "pw123", "1")
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	id2, err := db.CreateUser("norman", "pw456", "0")
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.RetrieveAllUsers()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 2 {
		t.Fatalf("One or more users weren't found in DB")
	}
	retrievedUser, err := db.RetrieveUser(strconv.FormatInt(id1, 10))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.Password), []byte("pw123")); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}

	if _, err = db.DeleteUser(strconv.FormatInt(id1, 10)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.RetrieveAllUsers()
	if len(res) != 1 {
		t.Fatalf("users weren't deleted from the DB properly")
	}

	_, err = db.UpdateUser(strconv.FormatInt(id2, 10), "thebestpassword")
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedUser, _ = db.RetrieveUser(strconv.FormatInt(id2, 10))
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.Password), []byte("thebestpassword")); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}

func Example() {
	db, err := certdb.NewCertificateRequestsRepository("./certs.db", "CertificateReq")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = db.CreateCSR(ValidCSR2)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = db.UpdateCSR(ValidCSR2, ValidCert2)
	if err != nil {
		log.Fatalln(err)
	}
	entry, err := db.RetrieveCSR(ValidCSR2)
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
