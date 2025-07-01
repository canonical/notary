package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestEncryptionKeyEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	encryptionKey, err := database.GetEncryptionKey()
	if err != nil {
		t.Fatalf("Couldn't get encryption key: %s", err)
	}
	if len(encryptionKey) == 0 {
		t.Fatalf("Expected an encryption key to be created on DB")
	}

	err = database.CreateEncryptionKey([]byte("test"))
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Expected an already exists error, got %s", err)
	}

	err = database.DeleteEncryptionKey()
	if err != nil {
		t.Fatalf("Couldn't delete encryption key: %s", err)
	}

	_, err = database.GetEncryptionKey()
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected a not found error, got %s", err)
	}

	err = database.CreateEncryptionKey([]byte("test1"))
	if err != nil {
		t.Fatalf("Couldn't create encryption key: %s", err)
	}

	// Get and verify the newly created encryption key
	if encryptionKey, err = database.GetEncryptionKey(); err != nil {
		t.Fatalf("Couldn't get encryption key: %s", err)
	}
	if string(encryptionKey) != "test1" {
		t.Fatalf("Encryption key is not 'test1'")
	}
}
