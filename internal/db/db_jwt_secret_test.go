package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestJWTSecretEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	jwtSecret, err := database.GetJWTSecret()
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}
	if jwtSecret != nil {
		t.Fatalf("JWT secret is not nil")
	}

	err = database.CreateJWTSecret([]byte("test"))
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret, err = database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(jwtSecret) != "test" {
		t.Fatalf("JWT secret is not 'test'")
	}

	err = database.CreateJWTSecret([]byte("test1"))
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Expected an already exists error, got %s", err)
	}

	err = database.DeleteJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't delete JWT secret: %s", err)
	}

	err = database.CreateJWTSecret([]byte("test2"))
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret, err = database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(jwtSecret) != "test2" {
		t.Fatalf("JWT secret is not 'test2'")
	}
}

func TestJWTSecretEncryption(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	originalSecret := []byte("super-secret-jwt-key")
	err := database.CreateJWTSecret(originalSecret)
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret := db.JWTSecret{ID: 1}
	row := database.Conn.PlainDB().QueryRow("SELECT * FROM jwt_secret WHERE id = ?", jwtSecret.ID)
	err = row.Scan(&jwtSecret.ID, &jwtSecret.EncryptedSecret)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if jwtSecret.EncryptedSecret == string(originalSecret) {
		t.Fatal("JWT secret is stored in plaintext!")
	}

	decryptedSecret, err := database.GetJWTSecret()
	if err != nil {
		t.Fatalf("Couldn't get JWT secret: %s", err)
	}
	if string(decryptedSecret) != string(originalSecret) {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			string(decryptedSecret), string(originalSecret))
	}

	decryptedManually, err := encryption.Decrypt(jwtSecret.EncryptedSecret, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != string(originalSecret) {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, string(originalSecret))
	}
}
