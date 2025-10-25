package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

type CreateBackupRequest struct {
	Path string `json:"path"`
}

type CreateBackupResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

func createBackup(url string, client *http.Client, token string, backupPath string) (int, *CreateBackupResponse, error) {
	reqData := CreateBackupRequest{
		Path: backupPath,
	}
	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest("POST", url+"/api/v1/backup", bytes.NewReader(jsonData))
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close() // nolint: errcheck

	var backupResponse CreateBackupResponse
	if err := json.NewDecoder(res.Body).Decode(&backupResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &backupResponse, nil
}

func TestBackupEndToEnd(t *testing.T) {
	ts, logs := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "manager@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	tempDir := t.TempDir()

	t.Run("1. Create backup - no authentication", func(t *testing.T) {
		statusCode, response, err := createBackup(ts.URL, client, "", tempDir)
		if err != nil {
			t.Fatalf("couldn't create backup: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected Unauthorized error when calling backup endpoint without authentication")
		}
	})

	t.Run("2. Create backup - non-admin token", func(t *testing.T) {
		statusCode, response, err := createBackup(ts.URL, client, nonAdminToken, tempDir)
		if err != nil {
			t.Fatalf("couldn't create backup: %s", err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected Forbidden error when calling backup endpoint with non-admin token")
		}
	})

	t.Run("3. Create backup - missing path", func(t *testing.T) {
		statusCode, response, err := createBackup(ts.URL, client, adminToken, "")
		if err != nil {
			t.Fatalf("couldn't create backup: %s", err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected error when calling backup endpoint without path")
		}
	})

	t.Run("4. Create backup - invalid path", func(t *testing.T) {
		invalidPath := "/nonexistent/invalid/path/that/does/not/exist"
		statusCode, response, err := createBackup(ts.URL, client, adminToken, invalidPath)
		if err != nil {
			t.Fatalf("couldn't create backup: %s", err)
		}
		if statusCode != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected error when calling backup endpoint with invalid path")
		}
	})

	t.Run("5. Create backup - admin token, valid path", func(t *testing.T) {
		_ = logs.TakeAll()
		statusCode, response, err := createBackup(ts.URL, client, adminToken, tempDir)
		if err != nil {
			t.Fatalf("couldn't create backup: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d. Error: %s", http.StatusOK, statusCode, response.Error)
		}
		if response.Error != "" {
			t.Fatalf("expected no error, got %q", response.Error)
		}
		if response.Result == "" {
			t.Fatalf("expected success message, got empty string")
		}

		files, err := os.ReadDir(tempDir)
		if err != nil {
			t.Fatalf("couldn't read temp dir: %s", err)
		}
		
		var backupFound bool
		for _, file := range files {
			if strings.HasPrefix(file.Name(), "backup_") && strings.HasSuffix(file.Name(), ".tar.gz") {
				backupFound = true
				info, err := os.Stat(filepath.Join(tempDir, file.Name()))
				if err != nil {
					t.Fatalf("couldn't stat backup file: %s", err)
				}
				if info.Size() == 0 {
					t.Fatalf("backup file is empty")
				}
				break
			}
		}
		if !backupFound {
			t.Fatalf("backup file not found in temp directory")
		}

		entries := logs.TakeAll()
		var haveBackupCreated bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == "backup_created" {
				haveBackupCreated = true
				loggedPath := findStringField(e, "backup_path")
				if loggedPath != tempDir {
					t.Fatalf("expected backup_path %q in audit log, got %q", tempDir, loggedPath)
				}
				actor := findStringField(e, "actor")
				if actor != "admin@canonical.com" {
					t.Fatalf("expected actor %q in audit log, got %q", "admin@canonical.com", actor)
				}
				break
			}
		}
		if !haveBackupCreated {
			t.Fatalf("expected backup_created audit entry")
		}
	})
}
