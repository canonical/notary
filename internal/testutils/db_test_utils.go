package testutils

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/db/migrations"
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

func MustPrepareEmptyDB(t *testing.T) *db.Database {
	t.Helper()

	tempDir := t.TempDir()
	sqlConnection, err := sql.Open("sqlite3", filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't create temporary database: %s", err)
	}
	goose.SetBaseFS(migrations.EmbedMigrations)
	err = goose.SetDialect("sqlite")
	if err != nil {
		t.Fatalf("Couldn't set goose dialect: %s", err)
	}
	err = goose.Up(sqlConnection, ".", goose.WithNoColor(true))
	if err != nil {
		t.Fatalf("Couldn't apply database migrations: %s", err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: filepath.Join(tempDir, "db.sqlite3"),
		Backend:      NoneEncryptionBackend,
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	t.Cleanup(func() {
		err := database.Close()
		if err != nil {
			t.Fatalf("Couldn't close database: %s", err)
		}
	})
	return database
}

var NoneEncryptionBackend = encryption_backend.NoEncryptionBackend{}

var logger, _ = zap.NewDevelopment()

var PublicConfig = config.PublicConfigData{
	Port:                  8000,
	PebbleNotifications:   false,
	LoggingLevel:          "debug",
	LoggingOutput:         "stdout",
	EncryptionBackendType: "none",
}
