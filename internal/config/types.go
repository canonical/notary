package config

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)

// VaultBackendConfigYaml BackendConfig for Vault-specific fields.
type VaultBackendConfigYaml struct {
	Endpoint         string `yaml:"endpoint"`
	Mount            string `yaml:"mount"`
	KeyName          string `yaml:"key_name"`
	Token            string `yaml:"token"`
	AppRoleID        string `yaml:"approle_role_id"`
	AppRoleSecretID  string `yaml:"approle_secret_id"`
	TlsCaCertificate string `yaml:"tls_ca_cert,omitempty"`     // Optional path to a CA file for Vault TLS verification
	TlsSkipVerify    bool   `yaml:"tls_skip_verify,omitempty"` // Optional flag to skip TLS verification
}

// PKCS11BackendConfigYaml BackendConfig for PKCS11-specific fields.
type PKCS11BackendConfigYaml struct {
	LibPath string `yaml:"lib_path"`
	KeyID   uint16 `yaml:"aes_encryption_key_id"`
	Pin     string `yaml:"pin"`
}

// NamedBackendConfigYaml represents a single named backend configuration
type NamedBackendConfigYaml struct {
	PKCS11 *PKCS11BackendConfigYaml `yaml:"pkcs11,omitempty"`
	Vault  *VaultBackendConfigYaml  `yaml:"vault,omitempty"`
}

type EncryptionBackendConfigYaml map[string]NamedBackendConfigYaml

type SystemLoggingConfigYaml struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type LoggingConfigYaml struct {
	System SystemLoggingConfigYaml `yaml:"system"`
}

type ConfigYAML struct {
	KeyPath             string                      `yaml:"key_path"`
	CertPath            string                      `yaml:"cert_path"`
	ExternalHostname    string                      `yaml:"external_hostname"`
	DBPath              string                      `yaml:"db_path"`
	Port                int                         `yaml:"port"`
	PebbleNotifications bool                        `yaml:"pebble_notifications"`
	Logging             LoggingConfigYaml           `yaml:"logging"`
	EncryptionBackend   EncryptionBackendConfigYaml `yaml:"encryption_backend"`
}

type LoggingLevel string

const (
	Debug LoggingLevel = "debug"
	Info  LoggingLevel = "info"
	Warn  LoggingLevel = "warn"
	Error LoggingLevel = "error"
	Fatal LoggingLevel = "fatal"
	Panic LoggingLevel = "panic"
)

type SystemLoggingOptions struct {
	Level  LoggingLevel
	Output string
}

type LoggerOptions struct {
	System SystemLoggingOptions
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
	// The YAML configuration file content
	Config       *ConfigYAML
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

	// Options for the logger
	Logger *zap.Logger

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
