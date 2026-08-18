package config

import (
	"github.com/canonical/notary/internal/acme"
	authn "github.com/canonical/notary/internal/backends/authentication"
	authz "github.com/canonical/notary/internal/backends/authorization"
	"github.com/canonical/notary/internal/backends/encryption"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/backends/observability/tracing"
	"github.com/canonical/notary/internal/cluster"
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

	// Path to store the sqlite database
	DBPath string
	// Whether to apply database migrations automatically on startup if the database is outdated
	ShouldApplyMigrations bool

	// ClusterConfig holds the dqlite clustering settings. Clustering is opt-in;
	// while it is disabled Notary stores its data in the single file at DBPath,
	// exactly as it always has.
	ClusterConfig ClusterConfig

	// Send pebble notifications if enabled. Read more at github.com/canonical/pebble
	ShouldEnablePebbleNotifications bool

	// Configurations for Subsystems
	LoggingConfig *viper.Viper
	TracingConfig *viper.Viper
	// OIDCConfig holds one entry per configured OIDC provider.
	OIDCConfig       []*viper.Viper
	EncryptionConfig *viper.Viper
}

// ClusterConfig holds the dqlite clustering settings.
type ClusterConfig struct {
	// Enabled turns on the clustered (dqlite) storage path.
	Enabled bool

	// StateDir holds this node's dqlite data and its cluster-internal PKI.
	StateDir string

	// Address is the address this node advertises to other cluster members for
	// dqlite and Raft traffic. It must be reachable by every other member.
	Address string
}

// AppEnvironment contains repositories and connections to external services that the application needs to run.
type AppEnvironment struct {
	Database *db.DatabaseRepository

	// ClusterNode is this node's dqlite cluster membership. It is nil when
	// clustering is disabled, which is what the cluster handlers check to decide
	// whether the cluster API is available at all.
	ClusterNode cluster.Node

	// ACMEReconciler tracks in-flight ACME issuance attempts so that ones
	// interrupted by a node failure can be reported as failed rather than left
	// pending forever.
	ACMEReconciler *acme.Reconciler

	SystemLogger *zap.Logger
	AuditLogger  *log.AuditLogger

	TracingRepository    *tracing.TracingRepository
	EncryptionRepository *encryption.EncryptionRepository
	AuthzRepository      *authz.AuthzRepository
	AuthnRepository      authn.OIDCProviders
}
