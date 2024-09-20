package server

import (
	"encoding/json"
	"net/http"
)

// the health check endpoint returns a http.StatusOK alongside info about the server
// initialized means the first user has been created
func HealthCheck(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := env.DB.RetrieveAllUsers()
		if err != nil {
			writeError("couldn't generate status", http.StatusInternalServerError, w)
			return
		}
		response, err := json.Marshal(map[string]any{
			"initialized": len(users) > 0,
		})
		if err != nil {
			writeError("couldn't generate status", http.StatusInternalServerError, w)
			return
		}
		w.Write(response)            //nolint:errcheck
		w.WriteHeader(http.StatusOK) //nolint:errcheck
	}
}
