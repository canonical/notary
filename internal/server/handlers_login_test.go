package server_test

import (
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
	"github.com/golang-jwt/jwt/v5"
)

func TestLoginEndToEnd(t *testing.T) {
	ts, logs := tu.MustPrepareServer(t)
	client := ts.Client()

	t.Run("Create admin user", func(t *testing.T) {
		// Get default admin token to create a new admin user
		defaultAdminToken := tu.MustGetDefaultAdminToken(t, ts)
		adminUser := &tu.CreateAccountParams{
			Email:    "testadmin@canonical.com",
			Password: "Admin123",
			RoleID:   tu.RoleAdmin,
		}
		statusCode, _, err := tu.CreateAccount(ts.URL, client, defaultAdminToken, adminUser)
		if err != nil {
			t.Fatalf("couldn't create admin user: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
	})

	t.Run("Login success", func(t *testing.T) {
		_ = logs.TakeAll()
		adminUser := &tu.LoginParams{
			Email:    "testadmin@canonical.com",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, adminUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if loginResponse.Data.Token == "" {
			t.Fatalf("expected token, got empty string")
		}
		token, _, err := jwt.NewParser().ParseUnverified(loginResponse.Data.Token, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("couldn't parse token: %s", err)
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if claims["email"] != "testadmin@canonical.com" {
				t.Fatalf("expected email %q, got %q", "testadmin@canonical.com", claims["email"])
			}
		}

		entries := logs.TakeAll()
		var haveLoginSuccess, haveTokenCreated bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			switch findStringField(e, "event") {
			case "authn_login_success:testadmin@canonical.com":
				haveLoginSuccess = true
			case "authn_token_created:testadmin@canonical.com":
				haveTokenCreated = true
			}
		}
		if !haveLoginSuccess {
			t.Fatalf("expected LoginSuccess audit entry")
		}
		if !haveTokenCreated {
			t.Fatalf("expected TokenCreated audit entry")
		}
	})

	t.Run("Login failure missing email", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Email:    "",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if loginResponse.Message != "email is required" {
			t.Fatalf("expected message %q, got %q", "email is required", loginResponse.Message)
		}
	})

	t.Run("Login failure missing password", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Email:    "testadmin@canonical.com",
			Password: "",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if loginResponse.Message != "password is required" {
			t.Fatalf("expected message %q, got %q", "password is required", loginResponse.Message)
		}
	})

	t.Run("Login failure invalid password (with audit)", func(t *testing.T) {
		_ = logs.TakeAll()
		invalidUser := &tu.LoginParams{
			Email:    "testadmin@canonical.com",
			Password: "a-wrong-password",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}
		if loginResponse.Message != "invalid credentials" {
			t.Fatalf("expected message %q, got %q", "invalid credentials", loginResponse.Message)
		}
		entries := logs.TakeAll()
		var haveLoginFailed bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == "authn_login_fail:testadmin@canonical.com" && findStringField(e, "reason") == "invalid credentials" {
				haveLoginFailed = true
				break
			}
		}
		if !haveLoginFailed {
			t.Fatalf("expected LoginFailed audit entry with reason 'invalid credentials'")
		}
	})

	t.Run("Login failure invalid email", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Email:    "not-existing-user",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}

		if loginResponse.Message != "invalid credentials" {
			t.Fatalf("expected message %q, got %q", "invalid credentials", loginResponse.Message)
		}
	})
}
