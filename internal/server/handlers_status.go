package server

import (
	"net/http"

	"github.com/canonical/notary/version"
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
			writeError(w, http.StatusInternalServerError, "couldn't generate status", err, env.SystemLogger)
			return
		}
		statusResponse := StatusResponse{
			Initialized: numUsers > 0,
			Version:     version.GetVersion(),
			OIDCEnabled: env.AuthnRepository != nil,
		}
		err = writeResponse(w, statusResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
