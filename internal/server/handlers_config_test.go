package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

type GetConfigContentResponse struct {
	Port                  int    `json:"port"`
	PebbleNotifications   bool   `json:"pebble_notifications"`
	LoggingLevel          string `json:"logging_level"`
	LoggingOutput         string `json:"logging_output"`
	EncryptionBackendType string `json:"encryption_backend_type"`
}

type GetConfigResponse struct {
	Result GetConfigContentResponse `json:"result"`
	Error  string                   `json:"error,omitempty"`
}

func getConfig(url string, client *http.Client, token string) (int, *GetConfigResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/config", nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var configResponse GetConfigResponse
	if err := json.NewDecoder(res.Body).Decode(&configResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &configResponse, nil
}

func TestConfigEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	t.Run("1. Get config - no authentication", func(t *testing.T) {
		statusCode, response, err := getConfig(ts.URL, client, "")
		if err != nil {
			t.Fatalf("couldn't get config: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}
		if response.Error == "" {
			t.Fatalf("expected Unauthorized error when calling the config endpoint without authentication")
		}
	})

	t.Run("2. Get config - admin token", func(t *testing.T) {
		statusCode, response, err := getConfig(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("couldn't get config: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected no error, got %q", response.Error)
		}

		if response.Result.Port == 0 {
			t.Fatalf("expected port to be set, got %d", response.Result.Port)
		}
		if response.Result.LoggingLevel == "" {
			t.Fatalf("expected logging level to be set, got %q", response.Result.LoggingLevel)
		}
		if response.Result.LoggingOutput == "" {
			t.Fatalf("expected logging output to be set, got %q", response.Result.LoggingOutput)
		}
		if response.Result.EncryptionBackendType == "" {
			t.Fatalf("expected encryption backend type to be set, got %q", response.Result.EncryptionBackendType)
		}
	})

	t.Run("3. Get config - non-admin token", func(t *testing.T) {
		statusCode, response, err := getConfig(ts.URL, client, nonAdminToken)
		if err != nil {
			t.Fatalf("couldn't get config: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected no error, got %q", response.Error)
		}
	})
}
