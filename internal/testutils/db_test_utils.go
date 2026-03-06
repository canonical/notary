package testutils

import (
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func MustPrepareEmptyDB(t *testing.T) *db.DatabaseRepository {
	t.Helper()

	tempDir := t.TempDir()
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath:    filepath.Join(tempDir, "db.sqlite"),
		ApplyMigrations: true,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}

	// Set up encryption key for the database
	encryptionBackend := &encryption.NoEncryptionBackend{}
	err = encryption.SetUpEncryptionKey(database, encryptionBackend, logger)
	if err != nil {
		t.Fatalf("Couldn't set up encryption key: %s", err)
	}

	// Set up JWT secret for the database
	err = authentication.SetUpJWTSecret(database)
	if err != nil {
		t.Fatalf("Couldn't set up JWT secret: %s", err)
	}

	t.Cleanup(func() {
		err := database.Close()
		if err != nil {
			t.Fatalf("Couldn't close database: %s", err)
		}
	})
	return database
}

var logger, _ = zap.NewDevelopment()

// MustCreateTestAppConfig creates a test AppConfig with reasonable defaults
func MustCreateTestAppConfig(t *testing.T) *config.AppConfig {
	t.Helper()

	// Create a default logging config using viper
	loggingConfig := viper.New()
	loggingConfig.SetDefault("system.output", "stdout")
	loggingConfig.SetDefault("system.level", "info")
	loggingConfig.SetDefault("audit.output", "stdout")
	loggingConfig.SetDefault("audit.level", "info")

	return &config.AppConfig{
		Port:                            8000,
		ExternalHostname:                "example.com",
		DBPath:                          ":memory:",
		ShouldApplyMigrations:           false,
		ShouldEnablePebbleNotifications: false,
		TLSCertificate:                  []byte(TestServerCertificate),
		TLSPrivateKey:                   []byte(TestServerKey),
		LoggingConfig:                   loggingConfig,
	}
}

// MustCreateTestAppEnvironment creates a test AppEnvironment with reasonable defaults
func MustCreateTestAppEnvironment(t *testing.T, database *db.DatabaseRepository) *config.AppEnvironment {
	t.Helper()
	encryptionRepo := &encryption.EncryptionRepository{
		Type:    encryption.EncryptionBackendTypeNone,
		Service: &encryption.NoEncryptionBackend{},
	}

	// Set up the encryption key in the database
	err := encryption.SetUpEncryptionKey(database, encryptionRepo.Service, logger)
	if err != nil {
		t.Fatalf("failed to set up encryption key: %s", err)
	}

	authzRepo, err := authorization.InitializeLocalOpenFGA(database, logger)
	if err != nil {
		t.Fatalf("failed to initialize OpenFGA: %s", err)
	}

	return &config.AppEnvironment{
		Database:             database,
		SystemLogger:         logger,
		AuditLogger:          nil, // Can be set up as needed
		EncryptionRepository: encryptionRepo,
		AuthzRepository:      authzRepo,
	}
}
