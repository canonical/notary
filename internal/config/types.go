package config

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/canonical/notary/internal/tracing"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)

type Tracer struct {
	Tracer       trace.Tracer
	ShutdownFunc tracing.TracerShutdownFunc
}

// PublicConfigData contains non-sensitive configuration fields that are safe to expose
type PublicConfigData struct {
	Port                  int
	PebbleNotifications   bool
	LoggingLevel          string
	LoggingOutput         string
	EncryptionBackendType EncryptionBackendType
}

type NotaryAppContext struct {
	PublicConfig *PublicConfigData

	// TLSPrivateKey and Certificate for the webserver and the listener port
	TLSPrivateKey  []byte
	TLSCertificate []byte

	// Port to be used for the Notary server
	Port int
	// ExternalHostname is used in the CRLDistributionPoint extension of the certificate
	ExternalHostname string

	// Path to store the database
	DBPath string
	// Whether to apply database migrations automatically on startup if the database is outdated
	ApplyMigrations bool

	// Send pebble notifications if enabled. Read more at github.com/canonical/pebble
	PebbleNotificationsEnabled bool

	// Options for the loggers and tracer
	SystemLogger *zap.Logger
	AuditLogger  *zap.Logger
	Tracer       *Tracer

	// Encryption backend to be used for encrypting and decrypting sensitive data
	EncryptionBackendType
	EncryptionBackend encryption_backend.EncryptionBackend

	// OIDC configuration
	OIDCConfig *OIDCConfig
}

// This is the configuration for OIDC authentication
type OIDCConfig struct {
	// This is the OIDC configuration of the configured server
	OIDCProvider *oidc.Provider
	// This is the oauth2 configuration for the IDP
	OAuth2Config *oauth2.Config
	// The audience is the value that the IDP will use to identify the Notary server with the correct API scopes
	Audience string
	// The issuer identifier for the OIDC provider, captured from discovery
	Issuer string
	// This is the key for the email claim in the access token
	EmailClaimKey string
	// This is the key for the permissions claim in the access token
	PermissionsClaimKey string
	// This is the key function for verifying the access token coming from the IDP
	KeyFunc keyfunc.Keyfunc
}
