package db_test

import (
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestPrivateKeysEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	pks, err := database.ListPrivateKeys()
	if err != nil {
		t.Fatalf("Couldn't list private keys: %s", err)
	}
	if len(pks) != 0 {
		t.Fatalf("Number of private keys is not 1")
	}

	err = database.CreatePrivateKey(selfSignedCACertificatePK)
	if err != nil {
		t.Fatalf("Couldn't create private key: %s", err)
	}

	pks, err = database.ListPrivateKeys()
	if err != nil {
		t.Fatalf("Couldn't list private keys: %s", err)
	}
	if len(pks) != 1 {
		t.Fatalf("Number of private keys is not 1")
	}

	pk, err := database.GetPrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if pk.PrivateKeyPEM != selfSignedCACertificatePK {
		t.Fatalf("Private key is not correct")
	}
	pk, err = database.GetPrivateKey(db.ByPrivateKeyPEM(selfSignedCACertificatePK))
	if err != nil {
		t.Fatalf("Couldn't get private key: %s", err)
	}
	if pk.PrivateKeyPEM != selfSignedCACertificatePK {
		t.Fatalf("Private key is not correct")
	}

	err = database.DeletePrivateKey(db.ByPrivateKeyID(1))
	if err != nil {
		t.Fatalf("Couldn't delete private key: %s", err)
	}

	pks, err = database.ListPrivateKeys()
	if err != nil {
		t.Fatalf("Couldn't list private keys: %s", err)
	}
	if len(pks) != 0 {
		t.Fatalf("Number of private keys is not 0")
	}
}

func TestPrivateKeyFails(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	err = database.CreatePrivateKey("")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}
	err = database.CreatePrivateKey("nope")
	if err == nil {
		t.Fatalf("Should have failed to create private key")
	}

	_, err = database.GetPrivateKey(db.ByPrivateKeyID(0))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetPrivateKey(db.ByPrivateKeyID(10))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetPrivateKey(db.ByPrivateKeyPEM(""))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetPrivateKey(db.ByPrivateKeyPEM("nope"))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}
	_, err = database.GetPrivateKey(db.ByPrivateKeyPEM(selfSignedCACertificatePK))
	if err == nil {
		t.Fatalf("Should have failed to get private key")
	}

	err = database.DeletePrivateKey(db.ByPrivateKeyPEM(selfSignedCACertificatePK))
	if err != nil {
		t.Fatalf("Couldn't delete private key: %s", err)
	}
}
