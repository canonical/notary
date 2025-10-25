package server

import (
	"encoding/json"
	"net/http"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
)

type CreateBackupRequest struct {
	Path string `json:"path"`
}

func CreateBackup(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CreateBackupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body", err, env.SystemLogger)
			return
		}
		if req.Path == "" {
			writeError(w, http.StatusBadRequest, "backup path is required", nil, env.SystemLogger)
			return
		}

		if err := db.CreateBackup(env.DB, req.Path); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create backup", err, env.SystemLogger)
			return
		}

		claims, err := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if err == nil {
			env.AuditLogger.BackupCreated(req.Path,
				logging.WithActor(claims.Email),
				logging.WithRequest(r),
			)
		}

		err = writeResponse(w, "Backup created", http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
