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
	ts, logs := tu.MustPrepareServer(t)
	client := ts.Client()
	// Use the default admin account (ID 1) instead of creating a new one
	adminToken := tu.MustGetDefaultAdminToken(t, ts)
	// Create a second admin account for testing purposes
	tu.MustPrepareAccount(t, ts, "testadmin@canonical.com", tu.RoleAdmin, adminToken)
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)

	t.Run("1. Get admin account - admin token", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Message != "" {
			t.Fatalf("expected message %q, got %q", "", response.Message)
		}
		if response.Data.ID != 1 {
			t.Fatalf("expected ID 1, got %d", response.Data.ID)
		}
		if response.Data.Email != "admin@notary.local" {
			t.Fatalf("expected email admin@notary.local, got %s", response.Data.Email)
		}
		if response.Data.RoleID != 0 {
			t.Fatalf("expected role ID 0, got %d", response.Data.RoleID)
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
		if response.Message != "forbidden: insufficient permissions" {
			t.Fatalf("expected message %q, got %q", "forbidden: insufficient permissions", response.Message)
		}
	})

	t.Run("3. Create account", func(t *testing.T) {
		_ = logs.TakeAll()
		createAccountParams := &tu.CreateAccountParams{
			Email:    "nopass@canonical.com",
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
		if response.Message != "" {
			t.Fatalf("unexpected message :%q", response.Message)
		}

		entries := logs.TakeAll()
		var haveUserCreated bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == ("user_created:" + createAccountParams.Email + ",admin") {
				haveUserCreated = true
				break
			}
		}
		if !haveUserCreated {
			t.Fatalf("expected UserCreated audit entry for %s", createAccountParams.Email)
		}
	})

	t.Run("4. Get account", func(t *testing.T) {
		statusCode, response, err := tu.GetAccount(ts.URL, client, adminToken, 4)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if response.Message != "" {
			t.Fatalf("expected message %q, got %q", "", response.Message)
		}
		if response.Data.ID != 4 {
			t.Fatalf("expected ID 4, got %d", response.Data.ID)
		}
		if response.Data.Email != "nopass@canonical.com" {
			t.Fatalf("expected email nopass@canonical.com, got %s", response.Data.Email)
		}
		if response.Data.RoleID != 1 {
			t.Fatalf("expected role ID 1, got %d", response.Data.RoleID)
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
		if response.Message != "not found" {
			t.Fatalf("expected message %q, got %q", "not found", response.Message)
		}
	})

	t.Run("6. Change account password - success", func(t *testing.T) {
		_ = logs.TakeAll()
		changeAccountPasswordParams := &tu.ChangeAccountPasswordParams{
			Password: "newPassword1",
		}
		statusCode, response, err := tu.ChangeAccountPassword(ts.URL, client, adminToken, 2, changeAccountPasswordParams)
		if err != nil {
			t.Fatalf("couldn't create account: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if response.Message != "" {
			t.Fatalf("unexpected message :%q", response.Message)
		}

		entries := logs.TakeAll()
		var havePwdChanged, haveUserUpdated bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			switch findStringField(e, "event") {
			case "authn_password_change:testadmin@canonical.com":
				havePwdChanged = true
			case "user_updated:testadmin@canonical.com,password_change":
				haveUserUpdated = true
			}
		}
		if !havePwdChanged {
			t.Fatalf("expected PasswordChanged audit entry")
		}
		if !haveUserUpdated {
			t.Fatalf("expected UserUpdated audit entry for password_change")
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
		if response.Message != "not found" {
			t.Fatalf("expected message %q, got %q", "not found", response.Message)
		}
	})

	t.Run("8. Delete account - success", func(t *testing.T) {
		_ = logs.TakeAll()
		statusCode, response, err := tu.DeleteAccount(ts.URL, client, adminToken, 3)
		if err != nil {
			t.Fatalf("couldn't delete account: %s", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
		if response.Message != "" {
			t.Fatalf("expected message %q, got %q", "", response.Message)
		}

		entries := logs.TakeAll()
		var haveUserDeleted bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == "user_deleted" && findStringField(e, "username") == "whatever@canonical.com" {
				haveUserDeleted = true
				break
			}
		}
		if !haveUserDeleted {
			t.Fatalf("expected UserDeleted audit entry for whatever@canonical.com")
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
		if response.Message != "not found" {
			t.Fatalf("expected message %q, got %q", "not found", response.Message)
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
		if response.Message != "" {
			t.Fatalf("expected message %q, got %q", "", response.Message)
		}
		if response.Data.ID != 1 {
			t.Fatalf("expected ID 1, got %d", response.Data.ID)
		}
		if response.Data.Email != "admin@notary.local" {
			t.Fatalf("expected email admin@notary.local, got %s", response.Data.Email)
		}
		if response.Data.RoleID != int(tu.RoleAdmin) {
			t.Fatalf("expected role ID %d, got %d", tu.RoleAdmin, response.Data.RoleID)
		}
		if !response.Data.HasPassword {
			t.Fatal("expected admin to have password")
		}
		if response.Data.HasOIDC {
			t.Fatal("expected admin to not have OIDC")
		}
		if len(response.Data.AuthMethods) != 1 || response.Data.AuthMethods[0] != "local" {
			t.Fatalf("expected auth methods [local], got %v", response.Data.AuthMethods)
		}
	})
}

func TestCreateAccountInvalidInputs(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	tests := []struct {
		testName string
		email    string
		password string
		roleID   tu.RoleID
		error    string
	}{
		{
			testName: "No email",
			email:    "",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "email is required",
		},
		{
			testName: "Invalid email - Missing @ symbol",
			email:    "invalid",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "invalid email format",
		},
		{
			testName: "Invalid email - Missing local part",
			email:    "@missinglocal.org",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "invalid email format",
		},
		{
			testName: "Invalid email - Domain starts with a dot",
			email:    "username@.com",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "invalid email format",
		},
		{
			testName: "Invalid email - Double dot",
			email:    "username@domain..com",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "invalid email format",
		},
		{
			testName: "Invalid email - Ends with dot",
			email:    "username@domain.com.",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "invalid email format",
		},

		{
			testName: "No password",
			email:    "test@canonical.com",
			password: "",
			roleID:   tu.RoleCertificateManager,
			error:    "password is required",
		},
		{
			testName: "bad password",
			email:    "test@canonical.com",
			password: "123",
			roleID:   tu.RoleCertificateManager,
			error:    "password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol",
		},
		{
			testName: "invalid role ID (negative)",
			email:    "test@canonical.com",
			password: "Pizza123!",
			roleID:   -1,
			error:    "invalid role ID: -1",
		},
		{
			testName: "invalid role ID (no matching role)",
			email:    "test@canonical.com",
			password: "Pizza123!",
			roleID:   999,
			error:    "invalid role ID: 999",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			createAccountParams := &tu.CreateAccountParams{
				Email:    test.email,
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
			if createCertResponse.Message != test.error {
				t.Fatalf("expected message %s, got %s", test.error, createCertResponse.Message)
			}
		})
	}
}

func TestChangeAccountPasswordInvalidInputs(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	tests := []struct {
		testName string
		password string
		error    string
	}{
		{
			testName: "No password",
			password: "",
			error:    "password is required",
		},
		{
			testName: "bad password",
			password: "123",
			error:    "password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol",
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
			if createCertResponse.Message != test.error {
				t.Fatalf("expected message %s, got %s", test.error, createCertResponse.Message)
			}
		})
	}
}
