package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

const testPrivKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4sONHKpVVIo7E4JWcKcxB5p2PTC\ntest-fake-key\n-----END RSA PRIVATE KEY-----"

const (
	testEmail        = "test@example.com"
	testDirectoryURL = "https://acme.example.com/directory"
	testRegURI       = "https://acme.example.com/acct/1"
	testRegBody      = `{"status":"valid"}`
)

func TestGetOrCreateACMEAccount_NewAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	account, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, testPrivKeyPEM, testRegURI, testRegBody)
	if err != nil {
		t.Fatalf("GetOrCreateACMEAccount() unexpected error: %v", err)
	}
	if account == nil {
		t.Fatal("expected non-nil account")
	}
	if account.Email != testEmail {
		t.Errorf("expected email %q, got %q", testEmail, account.Email)
	}
	if account.DirectoryURL != testDirectoryURL {
		t.Errorf("expected directory_url %q, got %q", testDirectoryURL, account.DirectoryURL)
	}
	if account.PrivateKeyPEM != testPrivKeyPEM {
		t.Errorf("expected plaintext private key, got %q", account.PrivateKeyPEM)
	}
	if account.RegistrationURI != testRegURI {
		t.Errorf("expected registration_uri %q, got %q", testRegURI, account.RegistrationURI)
	}
	if account.ID == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestGetOrCreateACMEAccount_ExistingAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	first, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, testPrivKeyPEM, testRegURI, testRegBody)
	if err != nil {
		t.Fatalf("first GetOrCreateACMEAccount() unexpected error: %v", err)
	}

	second, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, "different-key", "https://other", `{}`)
	if err != nil {
		t.Fatalf("second GetOrCreateACMEAccount() unexpected error: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("expected same ID on idempotent call: first=%d second=%d", first.ID, second.ID)
	}
	// Second call should return the same originally stored private key
	if second.PrivateKeyPEM != testPrivKeyPEM {
		t.Errorf("expected original private key on second call, got %q", second.PrivateKeyPEM)
	}
}

func TestGetOrCreateACMEAccount_DifferentURLCreatesNewAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	first, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, testPrivKeyPEM, testRegURI, testRegBody)
	if err != nil {
		t.Fatalf("first GetOrCreateACMEAccount() unexpected error: %v", err)
	}

	second, err := database.GetOrCreateACMEAccount(testEmail, "https://other.acme.example.com/directory", testPrivKeyPEM, testRegURI, testRegBody)
	if err != nil {
		t.Fatalf("second GetOrCreateACMEAccount() unexpected error: %v", err)
	}
	if first.ID == second.ID {
		t.Error("expected different IDs for different directory URLs")
	}
}

func TestACMEAccountPrivateKeyEncryptedAtRest(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	account, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, testPrivKeyPEM, testRegURI, `{}`)
	if err != nil {
		t.Fatalf("GetOrCreateACMEAccount() unexpected error: %v", err)
	}

	var rawKey string
	row := database.Conn.PlainDB().QueryRow(
		"SELECT private_key FROM acme_accounts WHERE id = ?", account.ID,
	)
	if err := row.Scan(&rawKey); err != nil {
		t.Fatalf("raw DB query failed: %v", err)
	}
	if rawKey == "" {
		t.Fatal("private_key stored in DB is empty")
	}
	if rawKey == testPrivKeyPEM {
		t.Fatal("private_key is stored in plaintext — expected it to be encrypted at rest")
	}
}

func TestGetDecryptedACMEAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	created, err := database.GetOrCreateACMEAccount(testEmail, testDirectoryURL, testPrivKeyPEM, testRegURI, testRegBody)
	if err != nil {
		t.Fatalf("GetOrCreateACMEAccount() unexpected error: %v", err)
	}

	fetched, err := database.GetDecryptedACMEAccount(created.ID)
	if err != nil {
		t.Fatalf("GetDecryptedACMEAccount() unexpected error: %v", err)
	}
	if fetched.Email != testEmail {
		t.Errorf("expected email %q, got %q", testEmail, fetched.Email)
	}
	if fetched.PrivateKeyPEM != testPrivKeyPEM {
		t.Errorf("decrypted private key mismatch: got %q", fetched.PrivateKeyPEM)
	}
	if fetched.RegistrationURI != testRegURI {
		t.Errorf("expected registration_uri %q, got %q", testRegURI, fetched.RegistrationURI)
	}
	if fetched.RegistrationBody != testRegBody {
		t.Errorf("expected registration_body %q, got %q", testRegBody, fetched.RegistrationBody)
	}
}

func TestGetDecryptedACMEAccount_NotFound(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.GetDecryptedACMEAccount(999)
	if err == nil {
		t.Fatal("expected error when no ACME account exists, got nil")
	}
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
