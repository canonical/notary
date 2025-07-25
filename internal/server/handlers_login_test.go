package server_test

import (
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
	"github.com/golang-jwt/jwt/v5"
)

func TestLoginEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()

	t.Run("Create admin user", func(t *testing.T) {
		adminUser := &tu.CreateAccountParams{
			Email:    "testadmin@canonical.com",
			Password: "Admin123",
			RoleID:   tu.RoleAdmin,
		}
		statusCode, _, err := tu.CreateAccount(ts.URL, client, "", adminUser)
		if err != nil {
			t.Fatalf("couldn't create admin user: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
	})

	t.Run("Login success", func(t *testing.T) {
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
		if loginResponse.Result.Token == "" {
			t.Fatalf("expected token, got empty string")
		}
		token, _, err := jwt.NewParser().ParseUnverified(loginResponse.Result.Token, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("couldn't parse token: %s", err)
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if claims["email"] != "testadmin@canonical.com" {
				t.Fatalf("expected email %q, got %q", "testadmin@canonical.com", claims["email"])
			}
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
		if loginResponse.Error != "Email is required" {
			t.Fatalf("expected error %q, got %q", "Email is required", loginResponse.Error)
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
		if loginResponse.Error != "Password is required" {
			t.Fatalf("expected error %q, got %q", "Password is required", loginResponse.Error)
		}
	})

	t.Run("Login failure invalid password", func(t *testing.T) {
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

		if loginResponse.Error != "The email or password is incorrect" {
			t.Fatalf("expected error %q, got %q", "The email or password is incorrect", loginResponse.Error)
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

		if loginResponse.Error != "The email or password is incorrect" {
			t.Fatalf("expected error %q, got %q", "The email or password is incorrect", loginResponse.Error)
		}
	})
}
