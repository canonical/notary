package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

type RestoreBackupRequest struct {
	File string `json:"file"`
}

type RestoreBackupResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

func restoreBackup(url string, client *http.Client, token string, backupFile string) (int, *RestoreBackupResponse, error) {
	reqData := RestoreBackupRequest{
		File: backupFile,
	}
	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest("POST", url+"/api/v1/restore", bytes.NewReader(jsonData))
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

	var restoreResponse RestoreBackupResponse
	if err := json.NewDecoder(res.Body).Decode(&restoreResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &restoreResponse, nil
}

func TestRestoreEndToEnd(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "manager@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	tempDir := t.TempDir()

	testDB := tu.MustPrepareEmptyDB(t)
	backupPath := filepath.Join(tempDir, "test_backup.tar.gz")
	
	if err := db.CreateBackup(testDB, tempDir); err != nil {
		t.Fatalf("couldn't create test backup: %s", err)
	}
	
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("couldn't read temp dir: %s", err)
	}
	
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".gz" {
			backupPath = filepath.Join(tempDir, file.Name())
			break
		}
	}

	t.Run("1. Restore backup - no authentication", func(t *testing.T) {
		statusCode, response, err := restoreBackup(ts.URL, client, "", backupPath)
		if err != nil {
			t.Fatalf("couldn't restore backup: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected Unauthorized error when calling restore endpoint without authentication")
		}
	})

	t.Run("2. Restore backup - non-admin token", func(t *testing.T) {
		statusCode, response, err := restoreBackup(ts.URL, client, nonAdminToken, backupPath)
		if err != nil {
			t.Fatalf("couldn't restore backup: %s", err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected Forbidden error when calling restore endpoint with non-admin token")
		}
	})

	t.Run("3. Restore backup - missing file", func(t *testing.T) {
		statusCode, response, err := restoreBackup(ts.URL, client, adminToken, "")
		if err != nil {
			t.Fatalf("couldn't restore backup: %s", err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected error when calling restore endpoint without file path")
		}
	})

	t.Run("4. Restore backup - non-existent file", func(t *testing.T) {
		nonExistentFile := "/nonexistent/invalid/path/backup.tar.gz"
		statusCode, response, err := restoreBackup(ts.URL, client, adminToken, nonExistentFile)
		if err != nil {
			t.Fatalf("couldn't restore backup: %s", err)
		}
		if statusCode != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected error when calling restore endpoint with non-existent file")
		}
	})

	t.Run("5. Restore backup - invalid backup file", func(t *testing.T) {
		invalidFile := filepath.Join(tempDir, "invalid.tar.gz")
		if err := os.WriteFile(invalidFile, []byte("not a valid tar.gz file"), 0600); err != nil {
			t.Fatalf("couldn't create invalid file: %s", err)
		}

		statusCode, response, err := restoreBackup(ts.URL, client, adminToken, invalidFile)
		if err != nil {
			t.Fatalf("couldn't restore backup: %s", err)
		}
		if statusCode != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected error when restoring invalid backup file")
		}
	})
}
