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
