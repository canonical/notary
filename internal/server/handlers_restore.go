package server

import (
	"encoding/json"
	"net/http"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
)

type RestoreBackupRequest struct {
	File string `json:"file"`
}

func RestoreBackup(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RestoreBackupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body", err, env.SystemLogger)
			return
		}
		if req.File == "" {
			writeError(w, http.StatusBadRequest, "backup file path is required", nil, env.SystemLogger)
			return
		}

		if err := db.RestoreBackup(env.DB, req.File); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to restore backup", err, env.SystemLogger)
			return
		}

		if claims, cerr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret, env.OIDCConfig); cerr == nil {
    		env.AuditLogger.BackupRestored(req.File,
    			logging.WithActor(claims.Email),
    			logging.WithRequest(r),
    		)
    	} else {
    		env.AuditLogger.BackupRestored(req.File,
    			logging.WithRequest(r),
    		)
    	}

		if err := writeResponse(w, "Backup restored", http.StatusOK); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

