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

// GetConfigContent godoc
//
//	@Summary		Get config
//	@Description	Returns the server configuration exposed to authenticated users.
//	@Tags			config
//	@Produce		json
//	@Success		200	{object}	map[string]GetConfigContentResponse
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/config [get]
func GetConfigContent(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configContent := GetConfigContentResponse{
			Port:                  env.Port,
			PebbleNotifications:   env.ShouldEnablePebbleNotifications,
			LoggingLevel:          env.SystemLogger.Level().String(),
			LoggingOutput:         env.LoggingConfig.GetString("system.output"),
			EncryptionBackendType: string(env.EncryptionRepository.Type),
		}
		writeResponse(w, http.StatusOK, "", configContent, env.SystemLogger)
	}
}
