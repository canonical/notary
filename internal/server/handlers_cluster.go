package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/cluster"
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
}

func AddClusterMember(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params addClusterMemberParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		name := params.ServerName
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		apiAddr, err := cluster.JoinAPIAddress(env.ClusterAddress, env.Port, env.ExternalHostname)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			return
		}
		token, err := cluster.IssueJoinTokenOnNode(ctx, env.Database.Node, env.Database.Conn.PlainDB(), name, env.Database.TLSCert, env.Database.TLSKey, env.TLSCertificate, []string{apiAddr})
		if err != nil {
			switch {
			case errors.Is(err, cluster.ErrMemberExists), errors.Is(err, cluster.ErrInvalidMemberName), errors.Is(err, cluster.ErrUnreachableJoinAddress):
				writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			default:
				env.SystemLogger.Error("failed to create join token", zap.Error(err))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			}
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
			switch {
			case errors.Is(err, cluster.ErrMemberNotFound):
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			case errors.Is(err, cluster.ErrLastMember), errors.Is(err, cluster.ErrInvalidMemberName):
				writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			default:
				env.SystemLogger.Error("failed to remove cluster member", zap.Error(err))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			}
			return
		}
		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

type joinClusterParams struct {
	JoinToken string `json:"join_token"`
}

func JoinCluster(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params joinClusterParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		token, err := cluster.DecodeJoinToken(params.JoinToken)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, err.Error(), nil, env.SystemLogger)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		material, err := cluster.RedeemJoinToken(ctx, env.Database.Conn.PlainDB(), token, env.Database.TLSCert, env.Database.TLSKey)
		if err != nil {
			switch {
			case cluster.JoinTokenRejected(err):
				writeResponse(w, http.StatusBadRequest, cluster.JoinTokenRejectedMessage, nil, env.SystemLogger)
			default:
				env.SystemLogger.Error("failed to redeem join token", zap.Error(err))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			}
			return
		}
		members, err := env.Database.ListClusterMembers(ctx)
		if err != nil {
			env.SystemLogger.Error("failed to list cluster members for join", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		addresses := make([]string, 0, len(members))
		for _, m := range members {
			if m.Address != "" {
				addresses = append(addresses, m.Address)
			}
		}
		if len(addresses) == 0 {
			env.SystemLogger.Error("cluster has no member addresses after redeeming join token")
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		env.SystemLogger.Info("redeemed cluster join token", zap.String("server_name", material.ServerName))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: map[string]any{
			"server_name":         material.ServerName,
			"cluster_certificate": string(material.TLSCert),
			"cluster_private_key": string(material.TLSKey),
			"addresses":           addresses,
		}})
	}
}
