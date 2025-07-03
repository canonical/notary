package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestPrivateKeysEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(1))
	if err == nil || !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound, got %s", err)
	}

	pkID, err := database.CreatePrivateKey(tu.RootCAPrivateKey)
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
	if pk.PrivateKeyPEM != tu.RootCAPrivateKey {
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
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreatePrivateKey("")
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
	database := tu.MustPrepareEmptyDB(t)

	pkID, err := database.CreatePrivateKey(tu.RootCAPrivateKey)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}

	pk := db.PrivateKey{PrivateKeyID: pkID}

	row := database.Conn.PlainDB().QueryRow("SELECT * FROM private_keys WHERE private_key_id = ?", pk.PrivateKeyID)
	err = row.Scan(&pk.PrivateKeyID, &pk.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("Couldn't query raw secret: %s", err)
	}

	if pk.PrivateKeyPEM == tu.RootCAPrivateKey {
		t.Fatal("Private key is stored in plaintext!")
	}

	decryptedPK, err := database.GetDecryptedPrivateKey(db.ByPrivateKeyID(pkID))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if decryptedPK.PrivateKeyPEM != tu.RootCAPrivateKey {
		t.Fatalf("Decrypted secret doesn't match original. Got %q, want %q",
			decryptedPK.PrivateKeyPEM, tu.RootCAPrivateKey)
	}

	decryptedManually, err := encryption.Decrypt(pk.PrivateKeyPEM, database.EncryptionKey)
	if err != nil {
		t.Fatalf("Couldn't manually decrypt secret: %s", err)
	}
	if decryptedManually != tu.RootCAPrivateKey {
		t.Fatalf("Manually decrypted secret doesn't match original. Got %q, want %q",
			decryptedManually, tu.RootCAPrivateKey)
	}
}
