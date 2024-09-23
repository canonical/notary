package server

import (
	"net/http"
)

type StatusResponse struct {
	Initialized bool `json:"initialized"`
}

// the GET status endpoint returns a http.StatusOK alongside info about the server
// initialized means the first user has been created
func GetStatus(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := env.DB.RetrieveAllUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "couldn't generate status")
			return
		}
		statusResponse := StatusResponse{
			Initialized: len(users) > 0,
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, statusResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
