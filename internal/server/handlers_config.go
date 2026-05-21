package server

import (
	"errors"
	"net/http"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

type GetConfigContentResponse struct {
	Port                  int    `json:"port"`
	PebbleNotifications   bool   `json:"pebble_notifications"`
	LoggingLevel          string `json:"logging_level"`
	LoggingOutput         string `json:"logging_output"`
	EncryptionBackendType string `json:"encryption_backend_type"`
	ACMEEnabled           bool   `json:"acme_enabled"`
	ACMEServerName        string `json:"acme_server_name,omitempty"`
}

func GetConfigContent(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var acmeEnabled bool
		var acmeServerName string
		activeServer, acmeErr := env.Database.GetActiveACMEServer()
		if acmeErr == nil && activeServer != nil {
			acmeEnabled = true
			acmeServerName = activeServer.Name
		} else if acmeErr != nil && !errors.Is(acmeErr, db.ErrNotFound) {
			env.SystemLogger.Error("failed to query active ACME server", zap.Error(acmeErr))
		}
		configContent := GetConfigContentResponse{
			Port:                  env.Port,
			PebbleNotifications:   env.ShouldEnablePebbleNotifications,
			LoggingLevel:          env.SystemLogger.Level().String(),
			LoggingOutput:         env.LoggingConfig.GetString("system.output"),
			EncryptionBackendType: string(env.EncryptionRepository.Type),
			ACMEEnabled:           acmeEnabled,
			ACMEServerName:        acmeServerName,
		}
		writeResponse(w, http.StatusOK, "", configContent, env.SystemLogger)
	}
}
