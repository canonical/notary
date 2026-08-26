package db_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

const testCAKeyPEM = "-----BEGIN PRIVATE KEY-----\nnot a real key, only bytes\n-----END PRIVATE KEY-----\n"

func TestClusterCAKeyRoundTrips(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.CreateClusterCAKey([]byte(testCAKeyPEM)); err != nil {
		t.Fatalf("couldn't store the cluster CA key: %s", err)
	}

	stored, err := database.GetClusterCAKey()
	if err != nil {
		t.Fatalf("couldn't read the cluster CA key: %s", err)
	}
	if !bytes.Equal(stored, []byte(testCAKeyPEM)) {
		t.Errorf("got %q, want %q", stored, testCAKeyPEM)
	}
}

// The key is what a stolen database dump must not yield, so the stored form has
// to differ from the plaintext.
func TestClusterCAKeyIsStoredEncrypted(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.CreateClusterCAKey([]byte(testCAKeyPEM)); err != nil {
		t.Fatalf("couldn't store the cluster CA key: %s", err)
	}

	var encrypted string
	row := database.Conn.PlainDB().QueryRow("SELECT encrypted_key FROM cluster_ca_key WHERE id = 1")
	if err := row.Scan(&encrypted); err != nil {
		t.Fatalf("couldn't read the stored row: %s", err)
	}
	if encrypted == testCAKeyPEM {
		t.Error("the cluster CA key is stored in plaintext")
	}
}

func TestCreateClusterCAKeyRejectsAnEmptyKey(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.CreateClusterCAKey(nil); !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}

// Restore clears the row the backup carried, and must not care whether the
// backup had one.
func TestDeleteClusterCAKeyIsIdempotent(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	if err := database.DeleteClusterCAKey(); err != nil {
		t.Fatalf("deleting an absent cluster CA key failed: %s", err)
	}

	if err := database.CreateClusterCAKey([]byte(testCAKeyPEM)); err != nil {
		t.Fatalf("couldn't store the cluster CA key: %s", err)
	}
	if err := database.DeleteClusterCAKey(); err != nil {
		t.Fatalf("couldn't delete the cluster CA key: %s", err)
	}
	if err := database.DeleteClusterCAKey(); err != nil {
		t.Fatalf("deleting twice failed: %s", err)
	}

	if _, err := database.GetClusterCAKey(); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}
