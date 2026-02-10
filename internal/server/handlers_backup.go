package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
)

type CreateBackupRequest struct {
	Path string `json:"path"`
}

// validateBackupPath validates that the backup path is safe and writable
func validateBackupPath(path string) error {
	if path == "" {
		return errors.New("backup path is required")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", absPath)
		}
		return fmt.Errorf("cannot access directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	return nil
}

func CreateBackup(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CreateBackupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body", err, env.SystemLogger)
			return
		}

		if err := validateBackupPath(req.Path); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), err, env.SystemLogger)
			return
		}

    	archivePath, err := db.CreateBackup(env.DB, req.Path)
    	if err != nil {
    		writeError(w, http.StatusInternalServerError, "failed to create backup", err, env.SystemLogger)
    		return
    	}

		if claims, cerr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret, env.OIDCConfig); cerr == nil {
    		env.AuditLogger.BackupCreated(req.Path,
    			logging.WithActor(claims.Email),
    			logging.WithRequest(r),
    		)
    	} else {
    		env.AuditLogger.BackupCreated(req.Path,
    			logging.WithRequest(r),
    		)
    	}

    	err = writeResponse(w, archivePath, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
