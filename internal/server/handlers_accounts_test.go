package server_test

import (
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

// This is an end-to-end test for the accounts handlers.
// The order of the tests is important, as some tests depend on
// the state of the server after previous tests.
func TestAccountsEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "testadmin", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever", tu.RoleCertificateManager, adminToken)

	t.Run("1. Get admin account - admin token", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected error %q, got %q", "", response.Error)
		}
		if response.Result.ID != 1 {
			t.Fatalf("expected ID 1, got %d", response.Result.ID)
		}
		if response.Result.Username != "testadmin" {
			t.Fatalf("expected username testadmin, got %s", response.Result.Username)
		}
		if response.Result.RoleID != 0 {
			t.Fatalf("expected role ID 0, got %d", response.Result.RoleID)
		}
	})

	t.Run("2. Get admin account - non admin token", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, nonAdminToken, 1)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
		}
		if response.Error != "forbidden: insufficient permissions" {
			t.Fatalf("expected error %q, got %q", "forbidden: insufficient permissions", response.Error)
		}
	})

	t.Run("3. Create account", func(t *testing.T) {
		createAccountParams := &tu.CreateAccountParams{
			Username: "nopass",
			Password: "myPassword123!",
			RoleID:   tu.RoleCertificateManager,
		}
		statusCode, response, err := tu.CreateAccount(ts.URL, client, adminToken, createAccountParams)
		if err != nil {
			t.Fatalf("couldn't create account: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("unexpected error :%q", response.Error)
		}
	})

	t.Run("4. Get account", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, adminToken, 3)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected error %q, got %q", "", response.Error)
		}
		if response.Result.ID != 3 {
			t.Fatalf("expected ID 3, got %d", response.Result.ID)
		}
		if response.Result.Username != "nopass" {
			t.Fatalf("expected username nopass, got %s", response.Result.Username)
		}
		if response.Result.RoleID != 1 {
			t.Fatalf("expected role ID 1, got %d", response.Result.RoleID)
		}
	})

	t.Run("5. Get account - id not found", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, adminToken, 100)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if response.Error != "Not Found" {
			t.Fatalf("expected error %q, got %q", "Not Found", response.Error)
		}
	})

	t.Run("6. Change account password - success", func(t *testing.T) {
		changeAccountPasswordParams := &tu.ChangeAccountPasswordParams{
			Password: "newPassword1",
		}
		statusCode, response, err := tu.ChangeAccountPassword(ts.URL, client, adminToken, 1, changeAccountPasswordParams)
		if err != nil {
			t.Fatalf("couldn't create account: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("unexpected error :%q", response.Error)
		}
	})

	t.Run("7. Change account password - no user", func(t *testing.T) {
		changeAccountPasswordParams := &tu.ChangeAccountPasswordParams{
			Password: "newPassword1",
		}
		statusCode, response, err := tu.ChangeAccountPassword(ts.URL, client, adminToken, 100, changeAccountPasswordParams)
		if err != nil {
			t.Fatalf("couldn't create account: %s", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if response.Error != "Not Found" {
			t.Fatalf("expected error %q, got %q", "Not Found", response.Error)
		}
	})

	t.Run("8. Delete account - success", func(t *testing.T) {
		statusCode, response, err := tu.DeleteAccount(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatalf("couldn't delete account: %s", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected error %q, got %q", "", response.Error)
		}
	})

	t.Run("9. Delete account - no user", func(t *testing.T) {
		statusCode, response, err := tu.DeleteAccount(ts.URL, client, adminToken, 100)
		if err != nil {
			t.Fatalf("couldn't delete account: %s", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if response.Error != "Not Found" {
			t.Fatalf("expected error %q, got %q", "Not Found", response.Error)
		}
	})

	t.Run("10. Get my admin account - admin token", func(t *testing.T) {
		statusCode, response, err := tu.GetMyAccount(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected error %q, got %q", "", response.Error)
		}
		if response.Result.ID != 1 {
			t.Fatalf("expected ID 1, got %d", response.Result.ID)
		}
		if response.Result.Username != "testadmin" {
			t.Fatalf("expected username testadmin, got %s", response.Result.Username)
		}
		if response.Result.RoleID != 0 {
			t.Fatalf("expected role ID 0, got %d", response.Result.RoleID)
		}
	})
}

func TestCreateAccountInvalidInputs(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin", tu.RoleAdmin, "")

	tests := []struct {
		testName string
		username string
		password string
		roleID   tu.RoleID
		error    string
	}{
		{
			testName: "No username",
			username: "",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: username is required",
		},
		{
			testName: "No password",
			username: "username",
			password: "",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: password is required",
		},
		{
			testName: "bad password",
			username: "username",
			password: "123",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
		},
		{
			testName: "invalid role ID (negative)",
			username: "username",
			password: "Pizza123!",
			roleID:   -1,
			error:    "Invalid request: invalid role ID: -1",
		},
		{
			testName: "invalid role ID (no matching role)",
			username: "username",
			password: "Pizza123!",
			roleID:   999,
			error:    "Invalid request: invalid role ID: 999",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			createAccountParams := &tu.CreateAccountParams{
				Username: test.username,
				Password: test.password,
				RoleID:   test.roleID,
			}
			statusCode, createCertResponse, err := tu.CreateAccount(ts.URL, client, adminToken, createAccountParams)
			if err != nil {
				t.Fatal(err)
			}
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
			}
			if createCertResponse.Error != test.error {
				t.Fatalf("expected error %s, got %s", test.error, createCertResponse.Error)
			}
		})
	}
}

func TestChangeAccountPasswordInvalidInputs(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin", tu.RoleAdmin, "")

	tests := []struct {
		testName string
		password string
		error    string
	}{
		{
			testName: "No password",
			password: "",
			error:    "Invalid request: password is required",
		},
		{
			testName: "bad password",
			password: "123",
			error:    "Invalid request: Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			changeAccountParams := &tu.ChangeAccountPasswordParams{
				Password: test.password,
			}
			statusCode, createCertResponse, err := tu.ChangeAccountPassword(ts.URL, client, adminToken, 1, changeAccountParams)
			if err != nil {
				t.Fatal(err)
			}
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
			}
			if createCertResponse.Error != test.error {
				t.Fatalf("expected error %s, got %s", test.error, createCertResponse.Error)
			}
		})
	}
}
