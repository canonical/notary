package server

import (
	"net/http"

	"github.com/canonical/notary/version"
)

type StatusResponse struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
}

// the GET status endpoint returns a http.StatusOK alongside info about the server
// initialized means the first user has been created
func GetStatus(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		numUsers, err := env.DB.NumUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "couldn't generate status", env.Logger)
			return
		}
		statusResponse := StatusResponse{
			Initialized: numUsers > 0,
			Version:     version.GetVersion(),
		}
		err = writeResponse(w, statusResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", env.Logger)
			return
		}
	}
}
