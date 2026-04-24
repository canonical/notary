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

// the GET status endpoint returns a http.StatusOK alongside info about the server
// initialized means the first user has been created
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
