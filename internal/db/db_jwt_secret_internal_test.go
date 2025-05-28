package db

import (
	"context"
	"path/filepath"
	"testing"
)

// TestJWTSecretEncryption verifies that the JWT secret is properly encrypted in the database
func TestJWTSecretEncryption(t *testing.T) {
	tempDir := t.TempDir()
	database, err := NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	originalSecret := []byte("super-secret-jwt-key")
	err = database.CreateJWTSecret(originalSecret)
	if err != nil {
		t.Fatalf("Couldn't create JWT secret: %s", err)
	}

	jwtSecret := JWTSecret{ID: 1}
	err = database.conn.Query(context.Background(), database.stmts.GetJWTSecret, jwtSecret).Get(&jwtSecret)
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

	decryptedManually, err := Decrypt(jwtSecret.EncryptedSecret, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != string(originalSecret) {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, string(originalSecret))
	}
}
