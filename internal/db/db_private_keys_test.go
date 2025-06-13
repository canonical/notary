package db_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption"
)

func TestPrivateKeysEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}

	pkID, err := database.CreatePrivateKey(RootCAPrivateKey)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}
	if pkID != 1 {
		t.Fatalf("Couldn't create private key: expected pk id 1, got %d", pkID)
	}

	pk, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if pk.PrivateKeyPEM != RootCAPrivateKey {
		t.Fatalf("Private key is not correct")
	}

	err = database.DeletePrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't delete private key: %s", err)
	}

	pk, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}
	if pk != nil {
		t.Fatalf("Private key is not nil")
	}
}

func TestPrivateKeyFails(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	_, err = database.CreatePrivateKey("")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}
	_, err = database.CreatePrivateKey("nope")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}

	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(0))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetDecryptedPrivateKey(db.ByPrivateKeyID(10))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
}

func TestPrivateKeyEncryption(t *testing.T) {
	tempDir := t.TempDir()
	databasePath := filepath.Join(tempDir, "db.sqlite3")
	database, err := db.NewDatabase(databasePath, NoneEncryptionBackend)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	pkID, err := database.CreatePrivateKey(RootCAPrivateKey)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}

	pk := db.PrivateKey{PrivateKeyID: pkID}
	sqlConnection, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		t.Fatalf("Couldn't open database: %s", err)
	}
	defer sqlConnection.Close()
	row := sqlConnection.QueryRow("SELECT * FROM private_keys WHERE private_key_id = ?", pk.PrivateKeyID)
	err = row.Scan(&pk.PrivateKeyID, &pk.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if pk.PrivateKeyPEM == RootCAPrivateKey {
		t.Fatal("Private key is stored in plaintext!")
	}

	decryptedPK, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(pkID))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if decryptedPK.PrivateKeyPEM != RootCAPrivateKey {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			decryptedPK.PrivateKeyPEM, RootCAPrivateKey)
	}

	decryptedManually, err := encryption.Decrypt(pk.PrivateKeyPEM, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != RootCAPrivateKey {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, RootCAPrivateKey)
	}
}
