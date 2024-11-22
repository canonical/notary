package db_test

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func TestConnect(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Can't connect to SQLite: %s", err)
	}
	db.Close()
}

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
	BananaCertBundle := strings.TrimSpace(fmt.Sprintf("%s%s", BananaCert, IssuerCert))
	err = db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, BananaCertBundle)
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedCSR, _ = db.GetCertificateRequestByCSR(BananaCSR)
	if retrievedCSR.CertificateChain != BananaCertBundle {
		t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSR.CertificateChain, BananaCertBundle)
	}
	err = db.RevokeCertificateByCSR(BananaCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Update to revoke certificate: %s", err)
	}
	err = db.RejectCertificateRequestByCSR(StrawberryCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Update to reject CSR: %s", err)
	}
	retrievedCSR, _ = db.GetCertificateRequestByCSR(BananaCSR)
	if retrievedCSR.Status != "Revoked" {
		t.Fatalf("Couldn't delete certificate")
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

func TestUpdateFails(t *testing.T) {
	db, _ := db.NewDatabase(":memory:")
	defer db.Close()

	db.CreateCertificateRequest(AppleCSR)  //nolint:errcheck
	db.CreateCertificateRequest(BananaCSR) //nolint:errcheck
	InvalidCert := strings.ReplaceAll(BananaCert, "/", "+")
	if err := db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, InvalidCert); err == nil {
		t.Fatalf("Expected updating with invalid cert to fail")
	}
	if err := db.AddCertificateChainToCertificateRequestByCSR(AppleCSR, BananaCert); err == nil {
		t.Fatalf("Expected updating with mismatched cert to fail")
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

func TestUsersEndToEnd(t *testing.T) {
	db, err := db.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer db.Close()

	err = db.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.CreateUser("norman", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.ListUsers()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 2 {
		t.Fatalf("One or more users weren't found in DB")
	}
	num, err := db.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("NumUsers didn't return the correct number of users")
	}
	retrievedUser, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	retrievedUser, err = db.GetUserByID(1)
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("pw123")); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
	if err = db.DeleteUserByID(1); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.ListUsers()
	if len(res) != 1 {
		t.Fatalf("users weren't deleted from the DB properly")
	}
	err = db.UpdateUserPassword(2, "thebestpassword")
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedUser, _ = db.GetUserByUsername("norman")
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("thebestpassword")); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
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
	entry, err := db.GetCertificateRequestByCSR(BananaCSR)
	if err != nil {
		log.Fatalln(err)
	}
	if entry.CertificateChain != BananaCert {
		log.Fatalln("Retrieved Certificate doesn't match Stored Certificate")
	}
	err = db.Close()
	if err != nil {
		log.Fatalln(err)
	}
}
