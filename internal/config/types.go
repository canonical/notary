package config

import (
	authn "github.com/canonical/notary/internal/backends/authentication"
	authz "github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/backends/observability/tracing"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// AppConfig contains parsed and validated configuration data without initialized subsystems
type AppConfig struct {
	// TLSPrivateKey and Certificate for the webserver and the listener port
	TLSPrivateKey  []byte
	TLSCertificate []byte

	// Port to be used for the Notary server
	Port int

	// ExternalHostname is used in the CRLDistributionPoint extension of the certificate
	// It is also used in the OIDC configuration as the audience for the IDP to identify the Notary server with the correct API scopes
	// TODO: this should be moved for separation of concerns
	ExternalHostname string

	// Path to store the sqlite database
	DBPath string
	// Whether to apply database migrations automatically on startup if the database is outdated
	ShouldApplyMigrations bool

	// Send pebble notifications if enabled. Read more at github.com/canonical/pebble
	ShouldEnablePebbleNotifications bool

	// Configurations for Subsystems
	LoggingConfig    *viper.Viper
	TracingConfig    *viper.Viper
	OIDCConfig       *viper.Viper
	EncryptionConfig *viper.Viper
}

// AppEnvironment contains repositories and connections to external services that the application needs to run.
type AppEnvironment struct {
	Database *db.DatabaseRepository

	SystemLogger *zap.Logger
	AuditLogger  *log.AuditLogger

	TracingRepository    *tracing.TracingRepository
	EncryptionRepository *encryption.EncryptionRepository
	AuthzRepository      *authz.OpenFGARepository
	AuthnRepository      *authn.OIDCRepository
}
