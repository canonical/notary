package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// CreateAutoSignPolicyParams holds the request body for creating an auto-sign policy.
type CreateAutoSignPolicyParams struct {
	Enabled                 *bool `json:"enabled"`
	CertificateValidityDays int   `json:"certificate_validity_days"`
	CertificateLimit        int   `json:"certificate_limit"`
}

// AutoSignPolicyResponse is the JSON response for auto-sign policy endpoints.
type AutoSignPolicyResponse struct {
	PolicyID                int64 `json:"policy_id"`
	CertificateAuthorityID  int64 `json:"certificate_authority_id"`
	Enabled                 bool  `json:"enabled"`
	CertificateValidityDays int   `json:"certificate_validity_days"`
	CertificateLimit        int   `json:"certificate_limit"`
}

func autoSignPolicyToResponse(p *db.AutoSignPolicy) AutoSignPolicyResponse {
	return AutoSignPolicyResponse{
		PolicyID:                p.PolicyID,
		CertificateAuthorityID:  p.CertificateAuthorityID,
		Enabled:                 p.Enabled,
		CertificateValidityDays: p.CertificateValidityDays,
		CertificateLimit:        p.CertificateLimit,
	}
}

// CreateAutoSignPolicy creates an auto-sign policy for a certificate authority.
func CreateAutoSignPolicy(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		caID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if err != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}
		_ = claims // claims not needed for create but validate auth

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityID(caID))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "certificate authority not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to check certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		var params CreateAutoSignPolicyParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			env.SystemLogger.Info("_invalid auto-sign create request JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}

		enabled := true
		if params.Enabled != nil {
			enabled = *params.Enabled
		}

		validity := params.CertificateValidityDays
		if validity == 0 {
			validity = 90
		}

		policy := db.AutoSignPolicy{
			CertificateAuthorityID:  caID,
			Enabled:                 enabled,
			CertificateValidityDays: validity,
			CertificateLimit:        params.CertificateLimit,
		}

		_, err = env.Database.GetAutoSignPolicy(caID)
		if err == nil {
			writeResponse(w, http.StatusConflict, "auto-sign policy already exists for this certificate authority", nil, env.SystemLogger)
			return
		} else if !errors.Is(err, db.ErrNotFound) {
			env.SystemLogger.Error("failed to check existing policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		policyID, err := env.Database.CreateAutoSignPolicy(policy)
		if err != nil {
			env.SystemLogger.Error("failed to create auto-sign policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		created, err := env.Database.GetAutoSignPolicy(caID)
		if err != nil {
			env.SystemLogger.Error("failed to get created policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, policyID)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}

		response := autoSignPolicyToResponse(created)
		writeResponse(w, http.StatusCreated, "", response, env.SystemLogger)
	}
}

// GetAutoSignPolicy gets the auto-sign policy for a certificate authority.
func GetAutoSignPolicy(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		caID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		policy, err := env.Database.GetAutoSignPolicy(caID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get auto-sign policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		response := autoSignPolicyToResponse(policy)
		writeResponse(w, http.StatusOK, "", response, env.SystemLogger)
	}
}

// UpdateAutoSignPolicy updates an auto-sign policy for a certificate authority.
func UpdateAutoSignPolicy(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		caID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		var params CreateAutoSignPolicyParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			env.SystemLogger.Info("invalid auto-sign update request JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}

		policy, err := env.Database.GetAutoSignPolicy(caID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get policy for update", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		if params.Enabled != nil {
			policy.Enabled = *params.Enabled
		}
		policy.CertificateValidityDays = params.CertificateValidityDays
		policy.CertificateLimit = params.CertificateLimit

		err = env.Database.UpdateAutoSignPolicy(*policy)
		if err != nil {
			env.SystemLogger.Error("failed to update policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		updated, err := env.Database.GetAutoSignPolicy(caID)
		if err != nil {
			env.SystemLogger.Error("failed to get updated policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, caID)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}

		response := autoSignPolicyToResponse(updated)
		writeResponse(w, http.StatusOK, "", response, env.SystemLogger)
	}
}

// DeleteAutoSignPolicy deletes an auto-sign policy for a certificate authority.
func DeleteAutoSignPolicy(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		caID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		err = env.Database.DeleteAutoSignPolicy(caID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete policy", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, caID)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}

		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}