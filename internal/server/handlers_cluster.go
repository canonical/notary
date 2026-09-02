package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

func ListClusterMembers(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		members, err := env.Database.ListClusterMembers(ctx)
		if err != nil {
			env.SystemLogger.Error("failed to list cluster members", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusOK, "", members, env.SystemLogger)
	}
}

type addClusterMemberParams struct {
	ServerName string `json:"server_name"`
	Name       string `json:"name"`
}

func AddClusterMember(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params addClusterMemberParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		name := params.ServerName
		if name == "" {
			name = params.Name
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		token, err := env.Database.IssueJoinToken(ctx, name)
		if err != nil {
			msg := err.Error()
			status := http.StatusInternalServerError
			if strings.Contains(msg, "already exists") || strings.Contains(msg, "invalid cluster member name") {
				status = http.StatusBadRequest
			}
			if status == http.StatusInternalServerError {
				env.SystemLogger.Error("failed to create join token", zap.Error(err))
				writeResponse(w, status, "", nil, env.SystemLogger)
				return
			}
			writeResponse(w, status, msg, nil, env.SystemLogger)
			return
		}
		writeResponse(w, http.StatusCreated, "", map[string]string{
			"server_name": name,
			"join_token":  token,
		}, env.SystemLogger)
	}
}

func RemoveClusterMember(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		err := env.Database.RemoveClusterMember(ctx, name)
		if err != nil {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "not found"):
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			case strings.Contains(msg, "last cluster member") || strings.Contains(msg, "invalid cluster member name"):
				writeResponse(w, http.StatusBadRequest, msg, nil, env.SystemLogger)
			default:
				env.SystemLogger.Error("failed to remove cluster member", zap.Error(err))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			}
			return
		}
		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}
