package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type LoginParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponseResult struct {
	Token string `json:"token"`
}

type LoginResponse struct {
	Result LoginResponseResult `json:"result"`
	Error  string              `json:"error,omitempty"`
}

func login(url string, client *http.Client, data *LoginParams) (int, *LoginResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/login", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var loginResponse LoginResponse
	if err := json.NewDecoder(res.Body).Decode(&loginResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &loginResponse, nil
}

func TestLoginEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	db_path := filepath.Join(tempDir, "db.sqlite3")
	ts, config, err := setupServer(db_path)
	if err != nil {
		t.Fatalf("couldn't create test server: %s", err)
	}
	defer ts.Close()
	client := ts.Client()

	t.Run("Create admin user", func(t *testing.T) {
		adminUser := &CreateAccountParams{
			Username: "testadmin",
			Password: "Admin123",
		}
		statusCode, _, err := createAccount(ts.URL, client, "", adminUser)
		if err != nil {
			t.Fatalf("couldn't create admin user: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
	})

	t.Run("Login success", func(t *testing.T) {
		adminUser := &LoginParams{
			Username: "testadmin",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := login(ts.URL, client, adminUser)
		if err != nil {
			t.Fatalf("couldn't login admin user: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if loginResponse.Result.Token == "" {
			t.Fatalf("expected token, got empty string")
		}
		token, err := jwt.Parse(loginResponse.Result.Token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return config.JWTSecret, nil
		})
		if err != nil {
			t.Fatalf("couldn't parse token: %s", err)
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["username"] != "testadmin" {
				t.Fatalf("expected username %q, got %q", "testadmin", claims["username"])
			}
		} else {
			t.Fatalf("invalid token or claims")
		}
	})

	t.Run("Login failure missing username", func(t *testing.T) {
		invalidUser := &LoginParams{
			Username: "",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := login(ts.URL, client, invalidUser)
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
		invalidUser := &LoginParams{
			Username: "testadmin",
			Password: "",
		}
		statusCode, loginResponse, err := login(ts.URL, client, invalidUser)
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
		invalidUser := &LoginParams{
			Username: "testadmin",
			Password: "a-wrong-password",
		}
		statusCode, loginResponse, err := login(ts.URL, client, invalidUser)
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
		invalidUser := &LoginParams{
			Username: "not-existing-user",
			Password: "Admin123",
		}
		statusCode, loginResponse, err := login(ts.URL, client, invalidUser)
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
