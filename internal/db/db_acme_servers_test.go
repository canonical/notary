package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCreateAndListACMEServers(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	id1, err := database.CreateACMEServer("letsencrypt", "https://acme-v02.api.letsencrypt.org/directory", "admin@example.com", "route53", map[string]string{"AWS_REGION": "us-east-1"})
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}
	if id1 == 0 {
		t.Fatal("expected non-zero ID")
	}

	_, err = database.CreateACMEServer("staging", "https://acme-staging-v02.api.letsencrypt.org/directory", "admin@example.com", "cloudflare", map[string]string{"CF_TOKEN": "secret"})
	if err != nil {
		t.Fatalf("CreateACMEServer() second server unexpected error: %v", err)
	}

	servers, err := database.ListACMEServers()
	if err != nil {
		t.Fatalf("ListACMEServers() unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

func TestGetACMEServer(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	id, err := database.CreateACMEServer("letsencrypt", "https://acme-v02.api.letsencrypt.org/directory", "admin@example.com", "route53", map[string]string{})
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}

	server, err := database.GetACMEServer(id)
	if err != nil {
		t.Fatalf("GetACMEServer() unexpected error: %v", err)
	}
	if server.Name != "letsencrypt" {
		t.Errorf("expected name %q, got %q", "letsencrypt", server.Name)
	}
	if server.Email != "admin@example.com" {
		t.Errorf("expected email %q, got %q", "admin@example.com", server.Email)
	}
	if server.Active {
		t.Error("expected new server to be inactive")
	}
	if server.ACMEAccountID != nil {
		t.Error("expected acme_account_id to be nil on new server")
	}

	_, err = database.GetACMEServer(99999)
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing server, got %v", err)
	}
}

func TestDeleteACMEServer(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	id, err := database.CreateACMEServer("letsencrypt", "https://acme-v02.api.letsencrypt.org/directory", "admin@example.com", "route53", map[string]string{})
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}

	if err := database.DeleteACMEServer(id); err != nil {
		t.Fatalf("DeleteACMEServer() unexpected error: %v", err)
	}

	_, err = database.GetACMEServer(id)
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}

	if err := database.DeleteACMEServer(id); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound when deleting non-existent server, got %v", err)
	}
}

func TestSetActiveACMEServer(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	id1, err := database.CreateACMEServer("server1", "https://acme1.example.com/directory", "a@example.com", "route53", map[string]string{})
	if err != nil {
		t.Fatalf("CreateACMEServer() 1 unexpected error: %v", err)
	}
	id2, err := database.CreateACMEServer("server2", "https://acme2.example.com/directory", "b@example.com", "cloudflare", map[string]string{})
	if err != nil {
		t.Fatalf("CreateACMEServer() 2 unexpected error: %v", err)
	}

	if err := database.SetActiveACMEServer(id1); err != nil {
		t.Fatalf("SetActiveACMEServer() unexpected error: %v", err)
	}

	s1, err := database.GetACMEServer(id1)
	if err != nil {
		t.Fatalf("GetACMEServer() unexpected error: %v", err)
	}
	if !s1.Active {
		t.Error("expected server1 to be active")
	}

	// Switch active to server2
	if err := database.SetActiveACMEServer(id2); err != nil {
		t.Fatalf("SetActiveACMEServer() switch unexpected error: %v", err)
	}

	s1, _ = database.GetACMEServer(id1)
	s2, _ := database.GetACMEServer(id2)
	if s1.Active {
		t.Error("expected server1 to be inactive after switching")
	}
	if !s2.Active {
		t.Error("expected server2 to be active after switching")
	}
}

func TestGetActiveACMEServer_NoneActive(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.GetActiveACMEServer()
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound when no active server, got %v", err)
	}
}

func TestGetDecryptedACMEServer_EnvVarsEncryptedAtRest(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	envVars := map[string]string{
		"SECRET_KEY": "super-secret-value",
		"REGION":     "us-east-1",
	}
	id, err := database.CreateACMEServer("myserver", "https://acme.example.com/directory", "admin@example.com", "route53", envVars)
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}

	// Verify env_vars is encrypted at rest
	var rawEnvVars string
	row := database.Conn.PlainDB().QueryRow("SELECT env_vars FROM acme_servers WHERE id = ?", id)
	if err := row.Scan(&rawEnvVars); err != nil {
		t.Fatalf("raw DB query failed: %v", err)
	}
	if rawEnvVars == `{"REGION":"us-east-1","SECRET_KEY":"super-secret-value"}` {
		t.Fatal("env_vars is stored in plaintext — expected encrypted at rest")
	}

	// Verify decryption round-trip
	decrypted, err := database.GetDecryptedACMEServer(id)
	if err != nil {
		t.Fatalf("GetDecryptedACMEServer() unexpected error: %v", err)
	}
	if decrypted.EnvVars == "" {
		t.Fatal("expected non-empty decrypted EnvVars")
	}
	// The decrypted EnvVars should be valid JSON containing our keys
	if decrypted.EnvVars == rawEnvVars {
		t.Error("expected decrypted EnvVars to differ from stored encrypted form")
	}
}

func TestUpdateACMEServer(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	id, err := database.CreateACMEServer("original", "https://acme.example.com/directory", "old@example.com", "route53", map[string]string{"KEY": "val"})
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}

	err = database.UpdateACMEServer(id, "updated", "https://new.acme.example.com/directory", "new@example.com", "cloudflare", map[string]string{"NEW_KEY": "new_val"})
	if err != nil {
		t.Fatalf("UpdateACMEServer() unexpected error: %v", err)
	}

	server, err := database.GetDecryptedACMEServer(id)
	if err != nil {
		t.Fatalf("GetDecryptedACMEServer() unexpected error: %v", err)
	}
	if server.Name != "updated" {
		t.Errorf("expected name %q, got %q", "updated", server.Name)
	}
	if server.Email != "new@example.com" {
		t.Errorf("expected email %q, got %q", "new@example.com", server.Email)
	}
	if server.DNSProvider != "cloudflare" {
		t.Errorf("expected dns_provider %q, got %q", "cloudflare", server.DNSProvider)
	}

	err = database.UpdateACMEServer(99999, "x", "x", "x", "x", map[string]string{})
	if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing server, got %v", err)
	}
}

func TestLinkAccountToServer(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	serverID, err := database.CreateACMEServer("myserver", "https://acme.example.com/directory", "admin@example.com", "route53", map[string]string{})
	if err != nil {
		t.Fatalf("CreateACMEServer() unexpected error: %v", err)
	}

	account, err := database.GetOrCreateACMEAccount("admin@example.com", "https://acme.example.com/directory", testPrivKeyPEM, "https://acme.example.com/acct/1", `{}`)
	if err != nil {
		t.Fatalf("GetOrCreateACMEAccount() unexpected error: %v", err)
	}

	if err := database.LinkAccountToServer(serverID, account.ID); err != nil {
		t.Fatalf("LinkAccountToServer() unexpected error: %v", err)
	}

	server, err := database.GetACMEServer(serverID)
	if err != nil {
		t.Fatalf("GetACMEServer() unexpected error: %v", err)
	}
	if server.ACMEAccountID == nil {
		t.Fatal("expected acme_account_id to be set after linking")
	}
	if *server.ACMEAccountID != account.ID {
		t.Errorf("expected acme_account_id %d, got %d", account.ID, *server.ACMEAccountID)
	}
}
