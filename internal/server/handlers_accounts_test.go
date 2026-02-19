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
	adminToken := tu.MustPrepareAccount(t, ts, "testadmin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)

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
		if response.Result.Email != "testadmin@canonical.com" {
			t.Fatalf("expected email testadmin@canonical.com, got %s", response.Result.Email)
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
		if response.Error != "" {
			t.Fatalf("unexpected error :%q", response.Error)
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
		if response.Result.Email != "nopass@canonical.com" {
			t.Fatalf("expected email nopass@canonical.com, got %s", response.Result.Email)
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
		_ = logs.TakeAll()
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
		if response.Error != "Not Found" {
			t.Fatalf("expected error %q, got %q", "Not Found", response.Error)
		}
	})

	t.Run("8. Delete account - success", func(t *testing.T) {
		_ = logs.TakeAll()
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
		if response.Result.Email != "testadmin@canonical.com" {
			t.Fatalf("expected email testadmin@canonical.com, got %s", response.Result.Email)
		}
		if response.Result.RoleID != int(tu.RoleAdmin) {
			t.Fatalf("expected role ID %d, got %d", tu.RoleAdmin, response.Result.RoleID)
		}
		if !response.Result.HasPassword {
			t.Fatal("expected admin to have password")
		}
		if response.Result.HasOIDC {
			t.Fatal("expected admin to not have OIDC")
		}
		if len(response.Result.AuthMethods) != 1 || response.Result.AuthMethods[0] != "local" {
			t.Fatalf("expected auth methods [local], got %v", response.Result.AuthMethods)
		}
	})

	t.Run("11. Update account role - success", func(t *testing.T) {
		_ = logs.TakeAll()
		statusCode, response, err := tu.UpdateAccountRole(ts.URL, client, adminToken, 3, &tu.UpdateAccountRoleParams{RoleID: tu.RoleReadOnly})
		if err != nil {
			t.Fatalf("couldn't update account role: %s", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("unexpected error :%q", response.Error)
		}

		statusCode, getResponse, err := tu.GetAccount(ts.URL, client, adminToken, 3)
		if err != nil {
			t.Fatalf("couldn't get account: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getResponse.Error != "" {
			t.Fatalf("expected error %q, got %q", "", getResponse.Error)
		}
		if getResponse.Result.RoleID != int(tu.RoleReadOnly) {
			t.Fatalf("expected role ID %d, got %d", tu.RoleReadOnly, getResponse.Result.RoleID)
		}

		entries := logs.TakeAll()
		var haveUserUpdated bool
		for _, e := range entries {
			if e.LoggerName != "audit" {
				continue
			}
			if findStringField(e, "event") == "user_updated:nopass@canonical.com,role_change" {
				haveUserUpdated = true
				break
			}
		}
		if !haveUserUpdated {
			t.Fatalf("expected UserUpdated audit entry for role_change")
		}
	})

	t.Run("12. Update account role - forbidden for non-admin", func(t *testing.T) {
		statusCode, response, err := tu.UpdateAccountRole(ts.URL, client, nonAdminToken, 3, &tu.UpdateAccountRoleParams{RoleID: tu.RoleCertificateManager})
		if err != nil {
			t.Fatalf("couldn't update account role: %s", err)
		}
		if statusCode != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, statusCode)
		}
		if response.Error != "forbidden: insufficient permissions" {
			t.Fatalf("expected error %q, got %q", "forbidden: insufficient permissions", response.Error)
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
			error:    "Invalid request: email is required",
		},
		{
			testName: "Invalid email - Missing @ symbol",
			email:    "invalid",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: invalid email format",
		},
		{
			testName: "Invalid email - Missing local part",
			email:    "@missinglocal.org",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: invalid email format",
		},
		{
			testName: "Invalid email - Domain starts with a dot",
			email:    "username@.com",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: invalid email format",
		},
		{
			testName: "Invalid email - Double dot",
			email:    "username@domain..com",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: invalid email format",
		},
		{
			testName: "Invalid email - Ends with dot",
			email:    "username@domain.com.",
			password: "password",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: invalid email format",
		},

		{
			testName: "No password",
			email:    "test@canonical.com",
			password: "",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: password is required",
		},
		{
			testName: "bad password",
			email:    "test@canonical.com",
			password: "123",
			roleID:   tu.RoleCertificateManager,
			error:    "Invalid request: password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol",
		},
		{
			testName: "invalid role ID (negative)",
			email:    "test@canonical.com",
			password: "Pizza123!",
			roleID:   -1,
			error:    "Invalid request: invalid role ID: -1",
		},
		{
			testName: "invalid role ID (no matching role)",
			email:    "test@canonical.com",
			password: "Pizza123!",
			roleID:   999,
			error:    "Invalid request: invalid role ID: 999",
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
			if createCertResponse.Error != test.error {
				t.Fatalf("expected error %s, got %s", test.error, createCertResponse.Error)
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
			error:    "Invalid request: password is required",
		},
		{
			testName: "bad password",
			password: "123",
			error:    "Invalid request: password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol",
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
