package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
)

// Creates an empty database for testing purposes.
func MustPrepareEmptyDB(t *testing.T) *db.Database {
	t.Helper()

	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend, logger)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	t.Cleanup(func() {
		database.Close()
	})
	return database
}

// Creates a mock database for testing purposes.
//
// Must result in a database with:
//   - 4 different types of users
//   - 1 Pending CSR
//   - 1 Signed CSR
//   - 1 Rejected CSR
//   - 1 Revoked CSR
//   - 1 Self Signed CA,
//   - 1 Intermediate CA (signed by Self Signed CA)
func MustPrepareMockDB(t *testing.T) *db.Database {
	t.Helper()

	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend, logger)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %v", err)
	}
	t.Cleanup(func() {
		database.Close()
	})

	// Create users
	_, err = database.CreateUser("admin-user", "password123", 0)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateUser("manager-user", "password123", 1)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateUser("requester-user", "password123", 2)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateUser("readonly-user", "password123", 3)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Create certificate requests
	// The permissions of the users that are the owners of the certificate requests are not checked.
	_, err = database.CreateCertificateRequest(AppleCSR, 1)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateCertificateRequest(BananaCSR, 1)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateCertificateRequest(StrawberryCSR, 2)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}
	_, err = database.CreateCertificateRequest(OrangeCSR, 2)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Create a self signed CA
	_, err = database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, 1)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Create an intermediate CA
	_, err = database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, IntermediateCACRL, IntermediateCACertificate+"\n"+RootCACertificate, 1)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Add certificate to BananaCSR
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(BananaCSR), BananaCertificate+"\n"+IntermediateCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Add certificate to StrawberryCSR
	_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRPEM(StrawberryCSR), StrawberryCertificate+"\n"+IntermediateCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// Reject StrawberryCSR
	err = database.RejectCertificateRequest(db.ByCSRPEM(StrawberryCSR))
	if err != nil {
		t.Fatalf("failed creating mock database: %v", err)
	}

	// execute select * on every table
	return database
}

func GenerateCSR() string {
	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create certificate request template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "notarytest.com",
			Organization: []string{"Canonical"},
		},
		DNSNames: []string{"notarytest.com", "www.notarytest.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		panic(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM)
}

var NoneEncryptionBackend = encryption_backend.NoEncryptionBackend{}

var logger, _ = zap.NewDevelopment()

var PublicConfig = config.PublicConfigData{
	Port:                  8000,
	PebbleNotifications:   false,
	LoggingLevel:          "debug",
	LoggingOutput:         "stdout",
	EncryptionBackendType: "none",
}
