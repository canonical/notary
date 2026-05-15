package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canonical/notary/internal/backends/authorization"
	internalLog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// mustPrepareServerWithoutAuthz creates a test server with AuthzRepository set to nil,
// simulating a deployment where OpenFGA is not configured. It also returns the database
// so callers can insert users directly (the API requires authorization, which is nil here).
func mustPrepareServerWithoutAuthz(t *testing.T) (*httptest.Server, *observer.ObservedLogs, *db.DatabaseRepository) {
	t.Helper()

	database := tu.MustPrepareEmptyDB(t)
	core, logs := observer.New(zapcore.InfoLevel)
	auditZap := zap.New(core)

	appCfg := tu.MustCreateTestAppConfig(t)

	appEnv := &config.AppEnvironment{
		Database:        database,
		SystemLogger:    zap.NewNop(),
		AuditLogger:     internalLog.NewAuditLogger(auditZap),
		AuthzRepository: nil,
	}

	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatalf("Couldn't create server: %s", err)
	}
	testServer := httptest.NewTLSServer(srv.Handler)
	t.Cleanup(func() {
		testServer.Close()
	})
	return testServer, logs, database
}

// TestBug_NilAuthzRepository_BypassesAuthorization demonstrates that when
// AuthzRepository is nil, requirePermission (middleware.go:251-254) skips all
// authorization checks and calls the handler directly. Any authenticated user
// can access admin-only endpoints.
func TestBug_NilAuthzRepository_BypassesAuthorization(t *testing.T) {
	ts, _, database := mustPrepareServerWithoutAuthz(t)
	client := ts.Client()

	// Insert reader user directly via DB — the account creation API requires
	// authorization, which is nil in this server, so the API would return 403.
	_, err := database.CreateUser("reader@test.com", "Reader123!", db.RoleReadOnly)
	if err != nil {
		t.Fatalf("failed to create reader in DB: %s", err)
	}

	loginParams := &tu.LoginParams{
		Email:    "reader@test.com",
		Password: "Reader123!",
	}
	statusCode, loginResp, err := tu.Login(ts.URL, client, loginParams)
	if err != nil {
		t.Fatalf("failed to login reader: %s", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
	}
	readerToken := loginResp.Data.Token

	t.Run("reader can list accounts (admin-only)", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/accounts", nil)
		if err != nil {
			t.Fatalf("failed to create request: %s", err)
		}
		req.Header.Set("Authorization", "Bearer "+readerToken)
		req.AddCookie(&http.Cookie{
			Name:     server.CookieSessionTokenKey,
			Value:    readerToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %s", err)
		}
		t.Cleanup(func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("failed to close response body: %s", err)
			}
		})

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("reader user got status %d accessing admin-only GET /accounts, expected 403", resp.StatusCode)
		}
	})

	t.Run("reader can create accounts (admin-only)", func(t *testing.T) {
		newAccountParams := &tu.CreateAccountParams{
			Email:    "created-by-reader@test.com",
			Password: "Testing123!",
			RoleID:   tu.RoleAdmin,
		}
		statusCode, _, err := tu.CreateAccount(ts.URL, client, readerToken, newAccountParams)
		if err != nil {
			t.Fatalf("failed to create account as reader: %s", err)
		}

		if statusCode != http.StatusForbidden {
			t.Errorf("reader user got status %d creating an admin account, expected 403", statusCode)
		}
	})
}

// TestBug_EmptyEmail_ProducesBrokenUserID demonstrates that
// authorization.UserID("") produces "user:" which is semantically invalid.
// In handlers_oidc.go:166, when an OIDC user authenticates without an email
// claim, WriteTuple is called with this broken ID. All email-less OIDC users
// would share the same authorization identity in OpenFGA.
func TestBug_EmptyEmail_ProducesBrokenUserID(t *testing.T) {
	userID := authorization.UserID("")

	if userID == "user:" {
		t.Errorf("UserID(\"\") produces %q, all email-less OIDC users share the same identity", userID)
	}
}
