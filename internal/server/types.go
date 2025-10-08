package server

import (
	"net/http"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
	"go.uber.org/zap"
)

type ServerOpts struct {
	TLSCertificate []byte
	TLSPrivateKey  []byte

	ExternalHostname string
	Port             int

	// Sends a notification to Pebble when an action is taken on a CSR.
	EnablePebbleNotifications bool

	// Config data to be returned in the API response.
	PublicConfig *config.PublicConfigData

	// Database object to run SQL queries on
	Database *db.Database

	SystemLogger *zap.Logger // For operational/system logs
	AuditLogger  *zap.Logger // For audit/compliance logs
	Tracer       *config.Tracer
}

// HandlerConfig holds the dependencies to be injected into the HTTP handlers for use during
// request processing.
type HandlerConfig struct {
	DB                      *db.Database
	SystemLogger            *zap.Logger
	AuditLogger             *logging.AuditLogger
	Tracer                  *config.Tracer
	ExternalHostname        string
	JWTSecret               []byte
	SendPebbleNotifications bool
	PublicConfig            config.PublicConfigData
}

type Server struct {
	*http.Server
}

type middleware func(http.Handler) http.Handler

type NotificationKey int
