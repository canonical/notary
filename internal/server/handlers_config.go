package server

import (
	"net/http"
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
		activeServer, acmeErr := env.Database.GetActiveACMEServer()
		var acmeServerName string
		if acmeErr == nil && activeServer != nil {
			acmeServerName = activeServer.Name
		}
		configContent := GetConfigContentResponse{
			Port:                  env.Port,
			PebbleNotifications:   env.ShouldEnablePebbleNotifications,
			LoggingLevel:          env.SystemLogger.Level().String(),
			LoggingOutput:         env.LoggingConfig.GetString("system.output"),
			EncryptionBackendType: string(env.EncryptionRepository.Type),
			ACMEEnabled:           acmeErr == nil,
			ACMEServerName:        acmeServerName,
		}
		writeResponse(w, http.StatusOK, "", configContent, env.SystemLogger)
	}
}
