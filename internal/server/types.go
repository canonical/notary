package server

import (
	"net/http"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
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

	Logger *zap.Logger
}

type Server struct {
	*http.Server
}

type middleware func(http.Handler) http.Handler

type NotificationKey int