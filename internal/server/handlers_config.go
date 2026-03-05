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
}

func GetConfigContent(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configContent := GetConfigContentResponse{
			Port:                  env.Port,
			PebbleNotifications:   env.ShouldEnablePebbleNotifications,
			LoggingLevel:          env.SystemLogger.Level().String(),
			LoggingOutput:         env.LoggingConfig.GetString("system.output"),
			EncryptionBackendType: string(env.EncryptionRepository.Type),
		}
		err := writeResponse(w, configContent, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
