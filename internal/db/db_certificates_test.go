package db_test

import (
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestCertificatesEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer db.Close()

	// create new certificate with 1 intermediate and 1 root certificate
	// create another certificate that shares the root certificate
	// validate there are 5 rows, and the tree is valid
	// validate the certificates still have the correct data in them

	// add a csr
	// add a new certificate that shares the intermediate certificate to the csr
	// validate that the csr points to the correct new certificate
	// validate that there are now 6 rows in the database, and that the tree of the new certificate is valid
	err = db.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.CreateCertificateRequest(BananaCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.AddCertificateChainToCertificateRequestByCSR(AppleCSR, AppleCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, BananaCert+IntermediateCert+RootCert)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	certs, err := db.ListCertificates()
	if err != nil {
		t.Fatalf("Couldn't complete List: %s", err)
	}
	if len(certs) != 5 {
		t.Fatalf("Expected 5 Certificates, only got %s", len(certs))
	}

	retrievedCSR, err := db.GetCertificateRequestAndChainByCSR(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedCSR.CSR != AppleCSR {
		t.Fatalf("The CSR from the database doesn't match the CSR that was given")
	}
	if retrievedCSR.CertificateID != 0 { //TODO: not equal to the id of the AppleCert id
		t.Fatalf("The certificate chain from the database doesn't match the certificate chain that was given")
	}

	if err = db.DeleteCertificateRequestByCSR(AppleCSR); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	// BananaCertBundle := strings.TrimSpace(fmt.Sprintf("%s%s", BananaCert, IssuerCert))
	// err = db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, BananaCertBundle)
	// if err != nil {
	// 	t.Fatalf("Couldn't complete Update: %s", err)
	// }
	// retrievedCSR, _ = db.GetCertificateRequestByCSR(BananaCSR)
	// if retrievedCSR.CertificateChain != BananaCertBundle {
	// 	t.Fatalf("The certificate that was uploaded does not match the certificate that was given.\n Retrieved: %s\nGiven: %s", retrievedCSR.CertificateChain, BananaCertBundle)
	// }
	// err = db.RevokeCertificateByCSR(BananaCSR)
	// if err != nil {
	// 	t.Fatalf("Couldn't complete Update to revoke certificate: %s", err)
	// }
	// err = db.RejectCertificateRequestByCSR(StrawberryCSR)
	// if err != nil {
	// 	t.Fatalf("Couldn't complete Update to reject CSR: %s", err)
	// }
	// retrievedCSR, _ = db.GetCertificateRequestByCSR(BananaCSR)
	// if retrievedCSR.Status != "Revoked" {
	// 	t.Fatalf("Couldn't delete certificate")
	// }
}

// test adding cert to csr fails
// func TestUpdateFails(t *testing.T) {
// 	db, _ := db.NewDatabase(":memory:")
// 	defer db.Close()

// 	db.CreateCertificateRequest(AppleCSR)  //nolint:errcheck
// 	db.CreateCertificateRequest(BananaCSR) //nolint:errcheck
// 	InvalidCert := strings.ReplaceAll(BananaCert, "/", "+")
// 	if err := db.AddCertificateChainToCertificateRequestByCSR(BananaCSR, InvalidCert); err == nil {
// 		t.Fatalf("Expected updating with invalid cert to fail")
// 	}
// 	if err := db.AddCertificateChainToCertificateRequestByCSR(AppleCSR, BananaCert); err == nil {
// 		t.Fatalf("Expected updating with mismatched cert to fail")
// 	}
// }
