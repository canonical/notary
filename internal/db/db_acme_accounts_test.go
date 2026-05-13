package db_test

import (
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

const testPrivKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4sONHKpVVIo7E4JWcKcxB5p2PTC\ntest-fake-key\n-----END RSA PRIVATE KEY-----"

func TestCreateACMEAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	err := database.CreateACMEAccount("test@example.com", testPrivKeyPEM, "https://acme.example.com/acct/1", `{"status":"valid"}`)
	if err != nil {
		t.Fatalf("CreateACMEAccount() unexpected error: %v", err)
	}
}

func TestGetDecryptedACMEAccount(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	email := "test@example.com"
	regURI := "https://acme.example.com/acct/1"
	regBody := `{"status":"valid"}`

	err := database.CreateACMEAccount(email, testPrivKeyPEM, regURI, regBody)
	if err != nil {
		t.Fatalf("CreateACMEAccount() unexpected error: %v", err)
	}

	account, err := database.GetDecryptedACMEAccount()
	if err != nil {
		t.Fatalf("GetDecryptedACMEAccount() unexpected error: %v", err)
	}
	if account.Email != email {
		t.Errorf("expected email %q, got %q", email, account.Email)
	}
	if account.PrivateKeyPEM != testPrivKeyPEM {
		t.Errorf("decrypted private key mismatch: got %q", account.PrivateKeyPEM)
	}
	if account.RegistrationURI != regURI {
		t.Errorf("expected registration_uri %q, got %q", regURI, account.RegistrationURI)
	}
	if account.RegistrationBody != regBody {
		t.Errorf("expected registration_body %q, got %q", regBody, account.RegistrationBody)
	}
}

// TestACMEAccountPrivateKeyEncryptedAtRest verifies that the private key stored
// in the raw database row is NOT the plaintext PEM — it must be encrypted.
func TestACMEAccountPrivateKeyEncryptedAtRest(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	err := database.CreateACMEAccount("test@example.com", testPrivKeyPEM, "https://acme.example.com/acct/1", `{}`)
	if err != nil {
		t.Fatalf("CreateACMEAccount() unexpected error: %v", err)
	}

	var rawAccount db.ACMEAccount
	row := database.Conn.PlainDB().QueryRow("SELECT id, email, private_key, registration_uri, registration_body FROM acme_accounts WHERE id = 1")
	err = row.Scan(&rawAccount.ID, &rawAccount.Email, &rawAccount.PrivateKeyPEM, &rawAccount.RegistrationURI, &rawAccount.RegistrationBody)
	if err != nil {
		t.Fatalf("raw DB query failed: %v", err)
	}
	if rawAccount.PrivateKeyPEM == "" {
		t.Fatal("private_key stored in DB is empty")
	}
	if rawAccount.PrivateKeyPEM == testPrivKeyPEM {
		t.Fatal("private_key is stored in plaintext — expected it to be encrypted at rest")
	}
}

// TestACMEAccountSingletonConstraint verifies that a second insert is rejected.
func TestACMEAccountSingletonConstraint(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	err := database.CreateACMEAccount("first@example.com", testPrivKeyPEM, "https://acme.example.com/acct/1", `{}`)
	if err != nil {
		t.Fatalf("first CreateACMEAccount() unexpected error: %v", err)
	}

	err = database.CreateACMEAccount("second@example.com", testPrivKeyPEM, "https://acme.example.com/acct/2", `{}`)
	if err == nil {
		t.Fatal("expected error on second CreateACMEAccount() (singleton constraint), got nil")
	}
}

func TestACMEAccountExists(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	exists, err := database.ACMEAccountExists()
	if err != nil {
		t.Fatalf("ACMEAccountExists() unexpected error before creation: %v", err)
	}
	if exists {
		t.Fatal("expected ACMEAccountExists() to return false before any account is created")
	}

	err = database.CreateACMEAccount("test@example.com", testPrivKeyPEM, "https://acme.example.com/acct/1", `{}`)
	if err != nil {
		t.Fatalf("CreateACMEAccount() unexpected error: %v", err)
	}

	exists, err = database.ACMEAccountExists()
	if err != nil {
		t.Fatalf("ACMEAccountExists() unexpected error after creation: %v", err)
	}
	if !exists {
		t.Fatal("expected ACMEAccountExists() to return true after account creation")
	}
}

// TestGetDecryptedACMEAccountNotFound verifies that GetDecryptedACMEAccount returns
// ErrNotFound when no account exists.
func TestGetDecryptedACMEAccountNotFound(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.GetDecryptedACMEAccount()
	if err == nil {
		t.Fatal("expected error when no ACME account exists, got nil")
	}
}
