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

func GetConfigContent(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configContent := GetConfigContentResponse{
			Port:                  env.PublicConfig.Port,
			PebbleNotifications:   env.PublicConfig.PebbleNotifications,
			LoggingLevel:          env.PublicConfig.LoggingLevel,
			LoggingOutput:         env.PublicConfig.LoggingOutput,
			EncryptionBackendType: string(env.PublicConfig.EncryptionBackendType),
		}
		err := writeResponse(w, configContent, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}
