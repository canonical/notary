package testutils

import (
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
)

func MustPrepareEmptyDB(t *testing.T) *db.Database {
	t.Helper()

	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"), NoneEncryptionBackend, logger)
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	t.Cleanup(func() {
		database.Close()
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
