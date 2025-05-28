package db_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
)

func TestJWTSecretEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()
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
