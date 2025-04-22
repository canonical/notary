// Contains helper functions for testing the server
package server_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"go.uber.org/zap"
)

func setupServer(filepath string) (*httptest.Server, *server.HandlerConfig, error) {
	testdb, err := db.NewDatabase(filepath)
	if err != nil {
		return nil, nil, err
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create logger: %w", err)
	}

	config := &server.HandlerConfig{
		DB:               testdb,
		ExternalHostname: "example.com",
		Logger:           logger.Sugar(),
	}
	ts := httptest.NewTLSServer(server.NewHandler(config))
	return ts, config, nil
}

func prepareAccounts(url string, client *http.Client, adminToken, nonAdminToken *string) func(*testing.T) {
	return func(t *testing.T) {
		adminAccountParams := &CreateAccountParams{
			Username: "testadmin",
			Password: "Admin123",
		}
		statusCode, _, err := createAccount(url, client, "", adminAccountParams)
		if err != nil {
			t.Fatalf("couldn't create admin account: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		adminLoginParams := &LoginParams{
			Username: adminAccountParams.Username,
			Password: adminAccountParams.Password,
		}
		statusCode, loginResponse, err := login(url, client, adminLoginParams)
		if err != nil {
			t.Fatalf("couldn't login admin account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		*adminToken = loginResponse.Result.Token

		nonAdminAccount := &CreateAccountParams{
			Username: "testuser",
			Password: "userPass!",
		}
		statusCode, _, err = createAccount(url, client, *adminToken, nonAdminAccount)
		if err != nil {
			t.Fatalf("couldn't create non-admin account: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}

		nonAdminLoginParams := &LoginParams{
			Username: nonAdminAccount.Username,
			Password: nonAdminAccount.Password,
		}
		statusCode, loginResponse, err = login(url, client, nonAdminLoginParams)
		if err != nil {
			t.Fatalf("couldn't login non-admin account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}

		*nonAdminToken = loginResponse.Result.Token
	}
}
