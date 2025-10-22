package config

import (
	"github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
)

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)

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

	// Options for the loggers
	SystemLogger *zap.Logger
	AuditLogger  *zap.Logger

	// Encryption backend to be used for encrypting and decrypting sensitive data
	EncryptionBackendType
	EncryptionBackend encryption_backend.EncryptionBackend
}
