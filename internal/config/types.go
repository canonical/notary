package config

import (
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/canonical/notary/internal/tracing"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type EncryptionBackendType string

const (
	EncryptionBackendTypeVault  = "vault"
	EncryptionBackendTypePKCS11 = "pkcs11"
	EncryptionBackendTypeNone   = "none"
)

type LoggingLevel string

const (
	Debug LoggingLevel = "debug"
	Info  LoggingLevel = "info"
	Warn  LoggingLevel = "warn"
	Error LoggingLevel = "error"
	Fatal LoggingLevel = "fatal"
	Panic LoggingLevel = "panic"
)

type Tracer struct {
	Tracer trace.Tracer
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
	// The YAML configuration file content
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

	// Options for the logger and tracer
	Logger *zap.Logger
	Tracer *Tracer

	// Encryption backend to be used for encrypting and decrypting sensitive data
	EncryptionBackendType
	EncryptionBackend encryption_backend.EncryptionBackend
}
