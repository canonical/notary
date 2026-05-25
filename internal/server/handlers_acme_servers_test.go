package server_test

import (
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

func TestACMEServersEndToEnd(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "acme-admin@canonical.com", tu.RoleAdmin, "")
	requestorToken := tu.MustPrepareAccount(t, ts, "acme-requestor@canonical.com", tu.RoleCertificateRequestor, adminToken)
	readerToken := tu.MustPrepareAccount(t, ts, "acme-reader@canonical.com", tu.RoleReadOnly, adminToken)
	client := ts.Client()

	var createdID int

	t.Run("1. List ACME servers - empty initially", func(t *testing.T) {
		statusCode, resp, err := tu.ListACMEServers(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}
		if len(resp.Data) != 0 {
			t.Fatalf("expected 0 ACME servers, got %d", len(resp.Data))
		}
	})

	t.Run("2. Create ACME server - missing required fields returns 400", func(t *testing.T) {
		statusCode, _, err := tu.CreateACMEServer(ts.URL, client, adminToken, tu.CreateACMEServerParams{
			Name: "incomplete",
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected %d, got %d", http.StatusBadRequest, statusCode)
		}
	})

	t.Run("3. Create ACME server - success", func(t *testing.T) {
		statusCode, resp, err := tu.CreateACMEServer(ts.URL, client, adminToken, tu.CreateACMEServerParams{
			Name:         "Let's Encrypt Staging",
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "admin@example.com",
			DNSProvider:  "cloudflare",
			EnvVars:      map[string]string{"CF_DNS_API_TOKEN": "test-token"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected %d, got %d: %s", http.StatusCreated, statusCode, resp.Message)
		}
		if resp.Data.Name != "Let's Encrypt Staging" {
			t.Fatalf("expected name 'Let's Encrypt Staging', got %s", resp.Data.Name)
		}
		if resp.Data.Active {
			t.Fatal("newly created server should not be active")
		}
		createdID = int(resp.Data.ID)
	})

	t.Run("4. Get ACME server by ID", func(t *testing.T) {
		statusCode, resp, err := tu.GetACMEServer(ts.URL, client, adminToken, createdID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}
		if resp.Data.ID != int64(createdID) {
			t.Fatalf("expected id %d, got %d", createdID, resp.Data.ID)
		}
		if resp.Data.DNSProvider != "cloudflare" {
			t.Fatalf("expected dns_provider 'cloudflare', got %s", resp.Data.DNSProvider)
		}
	})

	t.Run("5. Get ACME server - not found", func(t *testing.T) {
		statusCode, _, err := tu.GetACMEServer(ts.URL, client, adminToken, 99999)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
		}
	})

	t.Run("6. List ACME servers - one result", func(t *testing.T) {
		statusCode, resp, err := tu.ListACMEServers(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}
		if len(resp.Data) != 1 {
			t.Fatalf("expected 1 ACME server, got %d", len(resp.Data))
		}
	})

	t.Run("7. Update ACME server", func(t *testing.T) {
		statusCode, resp, err := tu.UpdateACMEServer(ts.URL, client, adminToken, createdID, tu.UpdateACMEServerParams{
			Name:         "Let's Encrypt Staging Updated",
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "updated@example.com",
			DNSProvider:  "hetzner",
			EnvVars:      map[string]string{"HETZNER_API_TOKEN": "new-token"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d: %s", http.StatusOK, statusCode, resp.Message)
		}
		if resp.Data.Email != "updated@example.com" {
			t.Fatalf("expected email 'updated@example.com', got %s", resp.Data.Email)
		}
		if resp.Data.DNSProvider != "hetzner" {
			t.Fatalf("expected dns_provider 'hetzner', got %s", resp.Data.DNSProvider)
		}
	})

	t.Run("8. Update ACME server - not found", func(t *testing.T) {
		statusCode, _, err := tu.UpdateACMEServer(ts.URL, client, adminToken, 99999, tu.UpdateACMEServerParams{
			Name:         "Ghost",
			DirectoryURL: "https://example.com",
			Email:        "x@x.com",
			DNSProvider:  "cloudflare",
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
		}
	})

	t.Run("9. Set active ACME server", func(t *testing.T) {
		statusCode, resp, err := tu.SetActiveACMEServer(ts.URL, client, adminToken, createdID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d: %s", http.StatusOK, statusCode, resp.Message)
		}
		if !resp.Data.Active {
			t.Fatal("expected server to be active after SetActive")
		}
	})

	t.Run("10. Set active - not found", func(t *testing.T) {
		statusCode, _, err := tu.SetActiveACMEServer(ts.URL, client, adminToken, 99999)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
		}
	})

	t.Run("11. Only one server active at a time", func(t *testing.T) {
		// Create a second server
		statusCode, resp2, err := tu.CreateACMEServer(ts.URL, client, adminToken, tu.CreateACMEServerParams{
			Name:         "Second Server",
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
			Email:        "admin2@example.com",
			DNSProvider:  "cloudflare",
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
		}
		secondID := int(resp2.Data.ID)

		// Activate the second one
		statusCode, _, err = tu.SetActiveACMEServer(ts.URL, client, adminToken, secondID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}

		// First should no longer be active
		statusCode, firstResp, err := tu.GetACMEServer(ts.URL, client, adminToken, createdID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}
		if firstResp.Data.Active {
			t.Fatal("expected first server to be inactive after second was activated")
		}

		// Clean up second server
		tu.DeleteACMEServer(ts.URL, client, adminToken, secondID) //nolint:errcheck
	})

	t.Run("12. Requestor cannot create ACME server", func(t *testing.T) {
		statusCode, _, err := tu.CreateACMEServer(ts.URL, client, requestorToken, tu.CreateACMEServerParams{
			Name:         "Unauthorized",
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Email:        "op@example.com",
			DNSProvider:  "cloudflare",
		})
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatalf("expected %d, got %d", http.StatusForbidden, statusCode)
		}
	})

	t.Run("13. Reader can list ACME servers", func(t *testing.T) {
		statusCode, _, err := tu.ListACMEServers(ts.URL, client, readerToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
		}
	})

	t.Run("14. Delete ACME server", func(t *testing.T) {
		statusCode, err := tu.DeleteACMEServer(ts.URL, client, adminToken, createdID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNoContent {
			t.Fatalf("expected %d, got %d", http.StatusNoContent, statusCode)
		}
	})

	t.Run("15. Delete ACME server - not found", func(t *testing.T) {
		statusCode, err := tu.DeleteACMEServer(ts.URL, client, adminToken, 99999)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
		}
	})

	t.Run("16. Get deleted ACME server - not found", func(t *testing.T) {
		statusCode, _, err := tu.GetACMEServer(ts.URL, client, adminToken, createdID)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
		}
	})
}

// TestACMEServerEnvVarKeysInResponse verifies that the API returns env_var_keys (the list
// of configured provider variable names) with values masked, rather than exposing the
// secrets. This covers the Create, Get, and Update response shapes.
func TestACMEServerEnvVarKeysInResponse(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "acme-admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// Create with two env vars.
	statusCode, created, err := tu.CreateACMEServer(ts.URL, client, adminToken, tu.CreateACMEServerParams{
		Name:         "Hetzner Server",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Email:        "ops@example.com",
		DNSProvider:  "hetzner",
		EnvVars: map[string]string{
			"HETZNER_API_TOKEN": "super-secret-token",
			"EXTRA_KEY":         "extra-value",
		},
	})
	if err != nil {
		t.Fatalf("CreateACMEServer() error: %v", err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, statusCode, created.Message)
	}

	// Create response must include env_var_keys with both key names.
	if len(created.Data.EnvVarKeys) != 2 {
		t.Fatalf("expected 2 env_var_keys in Create response, got %d: %v", len(created.Data.EnvVarKeys), created.Data.EnvVarKeys)
	}
	keySet := make(map[string]bool, len(created.Data.EnvVarKeys))
	for _, k := range created.Data.EnvVarKeys {
		keySet[k] = true
	}
	if !keySet["HETZNER_API_TOKEN"] || !keySet["EXTRA_KEY"] {
		t.Errorf("expected keys [HETZNER_API_TOKEN EXTRA_KEY] in Create response, got %v", created.Data.EnvVarKeys)
	}

	serverID := int(created.Data.ID)

	// Get response must also include the same env_var_keys.
	statusCode, fetched, err := tu.GetACMEServer(ts.URL, client, adminToken, serverID)
	if err != nil {
		t.Fatalf("GetACMEServer() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d from Get, got %d", http.StatusOK, statusCode)
	}
	if len(fetched.Data.EnvVarKeys) != 2 {
		t.Fatalf("expected 2 env_var_keys in Get response, got %d: %v", len(fetched.Data.EnvVarKeys), fetched.Data.EnvVarKeys)
	}

	// Update with a different set of env vars; response must reflect the new keys.
	statusCode, updated, err := tu.UpdateACMEServer(ts.URL, client, adminToken, serverID, tu.UpdateACMEServerParams{
		Name:         "Hetzner Server",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Email:        "ops@example.com",
		DNSProvider:  "hetzner",
		EnvVars:      map[string]string{"HETZNER_API_TOKEN": "rotated-token"},
	})
	if err != nil {
		t.Fatalf("UpdateACMEServer() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d from Update, got %d: %s", http.StatusOK, statusCode, updated.Message)
	}
	if len(updated.Data.EnvVarKeys) != 1 {
		t.Fatalf("expected 1 env_var_key after update, got %d: %v", len(updated.Data.EnvVarKeys), updated.Data.EnvVarKeys)
	}
	if updated.Data.EnvVarKeys[0] != "HETZNER_API_TOKEN" {
		t.Errorf("expected env_var_keys[0] to be %q, got %q", "HETZNER_API_TOKEN", updated.Data.EnvVarKeys[0])
	}

	// Update without env_vars: existing credentials must be preserved.
	statusCode, updated, err = tu.UpdateACMEServer(ts.URL, client, adminToken, serverID, tu.UpdateACMEServerParams{
		Name:         "Hetzner Server",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Email:        "ops@example.com",
		DNSProvider:  "hetzner",
		// EnvVars intentionally omitted
	})
	if err != nil {
		t.Fatalf("UpdateACMEServer() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d from Update (no env_vars), got %d: %s", http.StatusOK, statusCode, updated.Message)
	}
	if len(updated.Data.EnvVarKeys) != 1 {
		t.Fatalf("expected 1 env_var_key after omitted update, got %d: %v", len(updated.Data.EnvVarKeys), updated.Data.EnvVarKeys)
	}
	if updated.Data.EnvVarKeys[0] != "HETZNER_API_TOKEN" {
		t.Errorf("expected env_var_keys[0] to be %q, got %q", "HETZNER_API_TOKEN", updated.Data.EnvVarKeys[0])
	}

	// Update with explicit empty env_vars: wipes all credentials.
	statusCode, updated, err = tu.UpdateACMEServer(ts.URL, client, adminToken, serverID, tu.UpdateACMEServerParams{
		Name:         "Hetzner Server",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Email:        "ops@example.com",
		DNSProvider:  "hetzner",
		EnvVars:      map[string]string{},
	})
	if err != nil {
		t.Fatalf("UpdateACMEServer() error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d from Update (empty env_vars), got %d: %s", http.StatusOK, statusCode, updated.Message)
	}
	if len(updated.Data.EnvVarKeys) != 0 {
		t.Fatalf("expected 0 env_var_keys after empty env_vars update, got %d: %v", len(updated.Data.EnvVarKeys), updated.Data.EnvVarKeys)
	}
}
