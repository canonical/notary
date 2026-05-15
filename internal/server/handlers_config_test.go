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
	ACMEEnabled           bool   `json:"acme_enabled"`
	ACMEServerName        string `json:"acme_server_name,omitempty"`
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

// TestConfigACMEEnabledFalseByDefault verifies that acme_enabled is false
// when the default test database has no active ACME server configured.
func TestConfigACMEEnabledFalseByDefault(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	statusCode, response, err := getConfig(ts.URL, client, adminToken)
	if err != nil {
		t.Fatalf("couldn't get config: %s", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
	}
	if response.Data.ACMEEnabled {
		t.Fatal("expected acme_enabled to be false when no active ACME server is configured, got true")
	}
}

// TestConfigACMEEnabledTrueWhenServerActive verifies that acme_enabled is true and
// acme_server_name is set when there is an active ACME server configured at runtime.
func TestConfigACMEEnabledTrueWhenServerActive(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// Create an ACME server and set it active.
	statusCode, created, err := tu.CreateACMEServer(ts.URL, client, adminToken, tu.CreateACMEServerParams{
		Name:         "Test ACME",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Email:        "admin@example.com",
		DNSProvider:  "cloudflare",
	})
	if err != nil {
		t.Fatalf("CreateACMEServer() error: %v", err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d creating ACME server, got %d", http.StatusCreated, statusCode)
	}

	statusCode, _, err = tu.SetActiveACMEServer(ts.URL, client, adminToken, int(created.Data.ID))
	if err != nil {
		t.Fatalf("SetActiveACMEServer() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d setting active ACME server, got %d", http.StatusOK, statusCode)
	}

	// GET /config must now report acme_enabled: true and the server name.
	statusCode, response, err := getConfig(ts.URL, client, adminToken)
	if err != nil {
		t.Fatalf("getConfig() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d from GET /config, got %d", http.StatusOK, statusCode)
	}
	if !response.Data.ACMEEnabled {
		t.Fatal("expected acme_enabled to be true when an active ACME server is configured, got false")
	}
	if response.Data.ACMEServerName != "Test ACME" {
		t.Errorf("expected acme_server_name %q, got %q", "Test ACME", response.Data.ACMEServerName)
	}
}
