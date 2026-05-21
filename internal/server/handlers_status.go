package server

import (
	"net/http"

	"github.com/canonical/notary/version"
	"go.uber.org/zap"
)

type StatusResponse struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
	OIDCEnabled bool   `json:"oidc_enabled"`
}

// GetStatus godoc
//
//	@Summary		Get server status
//	@Description	Returns server status information, including initialization state, version, and whether OIDC is enabled.
//	@Tags			status
//	@Produce		json
//	@Success		200	{object}	map[string]StatusResponse
//	@Failure		500	{object}	map[string]string
//	@Router			/status [get]
func GetStatus(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := env.Database.NumUsers()
		if err != nil {
			env.SystemLogger.Error("failed to generate status", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		statusResponse := StatusResponse{
			Initialized: numUsers > 0,
			Version:     version.GetVersion(),
			OIDCEnabled: env.AuthnRepository != nil,
		}
		writeResponse(w, http.StatusOK, "", statusResponse, env.SystemLogger)
	}
}
