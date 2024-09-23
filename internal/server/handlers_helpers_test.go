// Contains helper functions for testing the server
package server_test

import (
	"net/http"
	"testing"
)

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

		*adminToken = string(loginResponse.Result.Token)

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

		*nonAdminToken = string(loginResponse.Result.Token)
	}
}
