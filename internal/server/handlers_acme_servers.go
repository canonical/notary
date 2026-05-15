package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

type ACMEServerResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	DNSProvider  string `json:"dns_provider"`
	Active       bool   `json:"active"`
}

type CreateACMEServerParams struct {
	Name         string            `json:"name"`
	DirectoryURL string            `json:"directory_url"`
	Email        string            `json:"email"`
	DNSProvider  string            `json:"dns_provider"`
	EnvVars      map[string]string `json:"env_vars"`
}

type UpdateACMEServerParams struct {
	Name         string            `json:"name"`
	DirectoryURL string            `json:"directory_url"`
	Email        string            `json:"email"`
	DNSProvider  string            `json:"dns_provider"`
	EnvVars      map[string]string `json:"env_vars"`
}

func dbACMEServerToResponse(s *db.ACMEServer) ACMEServerResponse {
	return ACMEServerResponse{
		ID:           s.ID,
		Name:         s.Name,
		DirectoryURL: s.DirectoryURL,
		Email:        s.Email,
		DNSProvider:  s.DNSProvider,
		Active:       s.Active,
	}
}

func ListACMEServers(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		servers, err := env.Database.ListACMEServers()
		if err != nil {
			env.SystemLogger.Error("failed to list ACME servers", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		resp := make([]ACMEServerResponse, 0, len(servers))
		for i := range servers {
			resp = append(resp, dbACMEServerToResponse(&servers[i]))
		}
		writeResponse(w, http.StatusOK, "", resp, env.SystemLogger)
	}
}

func GetACMEServer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid id", nil, env.SystemLogger)
			return
		}
		server, err := env.Database.GetACMEServer(id)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get ACME server", zap.Error(err), zap.Int64("id", id))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusOK, "", dbACMEServerToResponse(server), env.SystemLogger)
	}
}

func CreateACMEServer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params CreateACMEServerParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid request body", nil, env.SystemLogger)
			return
		}
		if params.Name == "" || params.DirectoryURL == "" || params.Email == "" || params.DNSProvider == "" {
			writeResponse(w, http.StatusBadRequest, "name, directory_url, email, and dns_provider are required", nil, env.SystemLogger)
			return
		}
		if params.EnvVars == nil {
			params.EnvVars = map[string]string{}
		}
		newID, err := env.Database.CreateACMEServer(params.Name, params.DirectoryURL, params.Email, params.DNSProvider, params.EnvVars)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeResponse(w, http.StatusConflict, "ACME server already exists", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to create ACME server", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		server, err := env.Database.GetACMEServer(newID)
		if err != nil {
			env.SystemLogger.Error("failed to retrieve created ACME server", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusCreated, "", dbACMEServerToResponse(server), env.SystemLogger)
	}
}

func UpdateACMEServer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid id", nil, env.SystemLogger)
			return
		}
		var params UpdateACMEServerParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid request body", nil, env.SystemLogger)
			return
		}
		if params.EnvVars == nil {
			params.EnvVars = map[string]string{}
		}
		if err := env.Database.UpdateACMEServer(id, params.Name, params.DirectoryURL, params.Email, params.DNSProvider, params.EnvVars); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to update ACME server", zap.Error(err), zap.Int64("id", id))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		server, err := env.Database.GetACMEServer(id)
		if err != nil {
			env.SystemLogger.Error("failed to retrieve updated ACME server", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusOK, "", dbACMEServerToResponse(server), env.SystemLogger)
	}
}

func DeleteACMEServer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid id", nil, env.SystemLogger)
			return
		}
		if err := env.Database.DeleteACMEServer(id); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete ACME server", zap.Error(err), zap.Int64("id", id))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusNoContent, "", nil, env.SystemLogger)
	}
}

func SetActiveACMEServer(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid id", nil, env.SystemLogger)
			return
		}
		if err := env.Database.SetActiveACMEServer(id); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to set active ACME server", zap.Error(err), zap.Int64("id", id))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		server, err := env.Database.GetACMEServer(id)
		if err != nil {
			env.SystemLogger.Error("failed to retrieve ACME server after activation", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusOK, "", dbACMEServerToResponse(server), env.SystemLogger)
	}
}

