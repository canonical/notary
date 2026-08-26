package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestEmbeddedSchemaVersionMatchesAMigratedDatabase(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	embedded, err := db.EmbeddedSchemaVersion()
	if err != nil {
		t.Fatalf("Couldn't read the embedded schema version: %s", err)
	}
	applied, err := database.SchemaVersion()
	if err != nil {
		t.Fatalf("Couldn't read the applied schema version: %s", err)
	}
	if embedded != applied {
		t.Fatalf("a fully migrated database is at version %d, but this binary embeds %d", applied, embedded)
	}
	if err := database.CheckSchemaVersion(embedded); err != nil {
		t.Fatalf("a matching version was rejected: %s", err)
	}
}

func TestCheckSchemaVersionRejectsAMismatch(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	applied, err := database.SchemaVersion()
	if err != nil {
		t.Fatalf("Couldn't read the applied schema version: %s", err)
	}

	for _, version := range []int64{applied - 1, applied + 1} {
		err := database.CheckSchemaVersion(version)
		if !errors.Is(err, db.ErrSchemaVersionMismatch) {
			t.Errorf("version %d: got %v, want ErrSchemaVersionMismatch", version, err)
		}
	}
}
