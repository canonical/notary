package db

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/canonical/notary/internal/db/migrations"
	"github.com/pressly/goose/v3"
)

// ErrSchemaVersionMismatch reports a node whose migrations differ from the ones
// applied to the cluster's replicated database.
var ErrSchemaVersionMismatch = errors.New("schema version mismatch")

// EmbeddedSchemaVersion is the newest migration version compiled into this
// binary.
func EmbeddedSchemaVersion() (int64, error) {
	entries, err := fs.ReadDir(migrations.EmbedMigrations, ".")
	if err != nil {
		return 0, fmt.Errorf("failed to read the embedded migrations: %w", err)
	}

	var latest int64
	for _, entry := range entries {
		version, err := goose.NumericComponent(entry.Name())
		if err != nil {
			return 0, fmt.Errorf("failed to read the version of migration %q: %w", entry.Name(), err)
		}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, errors.New("no embedded migrations found")
	}

	return latest, nil
}

// SchemaVersion returns the migration version applied to the database.
func (db *DatabaseRepository) SchemaVersion() (int64, error) {
	version, err := goose.GetDBVersion(db.Conn.PlainDB())
	if err != nil {
		return 0, fmt.Errorf("failed to read the applied schema version: %w", err)
	}
	return version, nil
}

// CheckSchemaVersion reports whether a node built against nodeVersion may take
// part in the cluster this database belongs to.
//
// Nothing in dqlite stops a node from replicating a schema its binary was not
// built for, so this is what keeps a rolling upgrade honest: the node that is
// out of step refuses to serve rather than reading columns it does not know
// about, or writing ones its peers have never heard of.
func (db *DatabaseRepository) CheckSchemaVersion(nodeVersion int64) error {
	applied, err := db.SchemaVersion()
	if err != nil {
		return err
	}
	if nodeVersion != applied {
		return fmt.Errorf("%w: this node is built for migration %d, the cluster is at migration %d",
			ErrSchemaVersionMismatch, nodeVersion, applied)
	}
	return nil
}
