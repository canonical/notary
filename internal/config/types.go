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
	ExternalHostname string

	// Path to the dqlite data directory.
	DBPath string

	// ClusterAddress is the dqlite bind address (host:port).
	ClusterAddress string

	// ClusterName is this node's LXD-style member name.
	ClusterName string

	// ClusterJoin is existing dqlite addresses. Used only the first time this
	// node starts with an empty data directory.
	ClusterJoin []string

	// ClusterJoinToken is a token from `notary cluster add`. Used only on first start.
	ClusterJoinToken string

	// ClusterTLSCertificate and ClusterTLSPrivateKey are the shared dqlite
	// cluster certificate (PEM). Required when ClusterJoin is set.
	ClusterTLSCertificate []byte
	ClusterTLSPrivateKey  []byte

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
	AuthzRepository      *authz.AuthzRepository
	AuthnRepository      *authn.OIDCRepository
}
