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
			Username: "testadmin",
			Password: "Admin123",
			RoleID:   0,
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
			Username: "testadmin",
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
			if claims["username"] != "testadmin" {
				t.Fatalf("expected username %q, got %q", "testadmin", claims["username"])
			}
		}
	})

	t.Run("Login failure missing username", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Username: "",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if loginResponse.Error != "Username is required" {
			t.Fatalf("expected error %q, got %q", "Username is required", loginResponse.Error)
		}
	})

	t.Run("Login failure missing password", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Username: "testadmin",
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
			Username: "testadmin",
			Password: "a-wrong-password",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}

		if loginResponse.Error != "The username or password is incorrect" {
			t.Fatalf("expected error %q, got %q", "The username or password is incorrect", loginResponse.Error)
		}
	})

	t.Run("Login failure invalid username", func(t *testing.T) {
		invalidUser := &tu.LoginParams{
			Username: "not-existing-user",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := tu.Login(ts.URL, client, invalidUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, statusCode)
		}

		if loginResponse.Error != "The username or password is incorrect" {
			t.Fatalf("expected error %q, got %q", "The username or password is incorrect", loginResponse.Error)
		}
	})
}
