package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/canonical/notary/internal/server"
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
	Message string                   `json:"message,omitempty"`
	Data    GetConfigContentResponse `json:"data"`
}

func getConfig(url string, client *http.Client, token string) (int, *GetConfigResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/config", nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.AddCookie(&http.Cookie{
			Name:     server.CookieSessionTokenKey,
			Value:    token,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close() // nolint: errcheck
	var configResponse GetConfigResponse
	if err := json.NewDecoder(res.Body).Decode(&configResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &configResponse, nil
}

func TestConfigEndToEnd(t *testing.T) {
	ts, logs := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	t.Run("1. Get config - no authentication", func(t *testing.T) {
		statusCode, response, err := getConfig(ts.URL, client, "")
		if err != nil {
			t.Fatalf("couldn't get config: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}
		if response.Message == "" {
			t.Fatalf("expected unauthorized message when calling the config endpoint without authentication")
		}
	})

	t.Run("2. Get config - admin token", func(t *testing.T) {
		_ = logs.TakeAll()
		statusCode, response, err := getConfig(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("couldn't get config: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Message != "" {
			t.Fatalf("expected no message, got %q", response.Message)
		}

		if response.Data.Port == 0 {
			t.Fatalf("expected port to be set, got %d", response.Data.Port)
		}
		if response.Data.LoggingLevel == "" {
			t.Fatalf("expected logging level to be set, got %q", response.Data.LoggingLevel)
		}
		if response.Data.LoggingOutput == "" {
			t.Fatalf("expected logging output to be set, got %q", response.Data.LoggingOutput)
		}
		if response.Data.EncryptionBackendType == "" {
			t.Fatalf("expected encryption backend type to be set, got %q", response.Data.EncryptionBackendType)
		}

		entries := logs.TakeAll()
		var haveAPISuccess bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == "api_action" && findStringField(e, "action") == "GET config" {
				haveAPISuccess = true
				break
			}
		}
		if !haveAPISuccess {
			t.Fatalf("expected APIAction success audit entry for GET config")
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
		if response.Message != "" {
			t.Fatalf("expected no message, got %q", response.Message)
		}
	})
}
