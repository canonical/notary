package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/hashing"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestUsersEndToEnd(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	userAdminEmail := "admin@canonical.com"
	userID, err := database.CreateUser(userAdminEmail, "pw123", 0)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	userNormanEmail := "norman@canonical.com"
	userID, err = database.CreateUser(userNormanEmail, "pw456", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if userID != 2 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", userID)
	}

	res, err := database.ListUsers()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 2 {
		t.Fatalf("One or more users weren't found in DB")
	}

	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("NumUsers didn't return the correct number of users")
	}

	retrievedUser, err := database.GetUser(db.ByEmail(userAdminEmail))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Email != userAdminEmail {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}

	retrievedUser, err = database.GetUser(db.ByUserID(userID))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Email != userNormanEmail {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := hashing.CompareHashAndPassword(*retrievedUser.HashedPassword, "pw456"); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}

	if err = database.DeleteUser(db.ByUserID(1)); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = database.ListUsers()
	if len(res) != 1 {
		t.Fatalf("users weren't deleted from the DB properly")
	}

	err = database.UpdateUserPassword(db.ByUserID(2), "thebestpassword")
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedUser, _ = database.GetUser(db.ByEmail(userNormanEmail))
	if err := hashing.CompareHashAndPassword(*retrievedUser.HashedPassword, "thebestpassword"); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}

// TestCreateOIDCUser tests creating a user without a password via OIDC
func TestCreateOIDCUser(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	email := "oidc@example.com"
	oidcSubject := "auth0|123456"
	user, err := database.CreateOIDCUser(email, oidcSubject, db.RoleReadOnly)
	if err != nil {
		t.Fatalf("Failed to create OIDC user: %s", err)
	}

	if user.ID == 0 {
		t.Fatal("User ID should not be 0")
	}
	if user.Email != email {
		t.Fatalf("Expected email %s, got %s", email, user.Email)
	}
	if !user.HasOIDC() {
		t.Fatal("User should have OIDC linked")
	}
	if user.HasPassword() {
		t.Fatal("OIDC-only user should not have password")
	}
	if user.OIDCSubject == nil || *user.OIDCSubject != oidcSubject {
		t.Fatalf("Expected OIDC subject %s, got %v", oidcSubject, user.OIDCSubject)
	}
	if user.RoleID != db.RoleReadOnly {
		t.Fatalf("Expected role RoleReadOnly, got %d", user.RoleID)
	}
}

// TestCreateOIDCUserDuplicateSubject tests that duplicate OIDC subjects are rejected
func TestCreateOIDCUserDuplicateSubject(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	oidcSubject := "auth0|duplicate"
	_, err := database.CreateOIDCUser("user1@example.com", oidcSubject, db.RoleReadOnly)
	if err != nil {
		t.Fatalf("Failed to create first OIDC user: %s", err)
	}

	// Try to create another user with same OIDC subject
	_, err = database.CreateOIDCUser("user2@example.com", oidcSubject, db.RoleReadOnly)
	if err == nil {
		t.Fatal("Should have failed when creating user with duplicate OIDC subject")
	}
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("Expected ErrAlreadyExists, got %v", err)
	}
}

// TestGetUserByOIDCSubject tests retrieving a user by OIDC subject
func TestGetUserByOIDCSubject(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	email := "oidc@example.com"
	oidcSubject := "auth0|test123"
	createdUser, err := database.CreateOIDCUser(email, oidcSubject, db.RoleReadOnly)
	if err != nil {
		t.Fatalf("Failed to create OIDC user: %s", err)
	}

	// Retrieve by OIDC subject
	retrievedUser, err := database.GetUser(db.ByOIDCSubject(oidcSubject))
	if err != nil {
		t.Fatalf("Failed to get user by OIDC subject: %s", err)
	}

	if retrievedUser.ID != createdUser.ID {
		t.Fatalf("Expected user ID %d, got %d", createdUser.ID, retrievedUser.ID)
	}
	if retrievedUser.Email != email {
		t.Fatalf("Expected email %s, got %s", email, retrievedUser.Email)
	}
}

// TestCreateOIDCUserWithoutEmail tests creating an OIDC user without an email
// Email should be optional - only the OIDC subject is required
func TestCreateOIDCUserWithoutEmail(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	oidcSubject := "auth0|no-email-user"
	user, err := database.CreateOIDCUser("", oidcSubject, db.RoleReadOnly)
	if err != nil {
		t.Fatalf("Failed to create OIDC user without email: %s", err)
	}

	if user.ID == 0 {
		t.Fatal("User ID should not be 0")
	}
	if user.Email != "" {
		t.Fatalf("Expected empty email, got %s", user.Email)
	}
	if !user.HasOIDC() {
		t.Fatal("User should have OIDC linked")
	}
	if user.HasPassword() {
		t.Fatal("OIDC-only user should not have password")
	}
	if user.OIDCSubject == nil || *user.OIDCSubject != oidcSubject {
		t.Fatalf("Expected OIDC subject %s, got %v", oidcSubject, user.OIDCSubject)
	}

	// Should be retrievable by OIDC subject
	retrievedUser, err := database.GetUser(db.ByOIDCSubject(oidcSubject))
	if err != nil {
		t.Fatalf("Failed to get user by OIDC subject: %s", err)
	}
	if retrievedUser.ID != user.ID {
		t.Fatalf("Expected user ID %d, got %d", user.ID, retrievedUser.ID)
	}
}

// TestUserHasPasswordHelper tests the HasPassword helper method
func TestUserHasPasswordHelper(t *testing.T) {
	// User with password
	userWithPassword := db.User{
		HashedPassword: stringPtr("hashed_password"),
	}
	if !userWithPassword.HasPassword() {
		t.Fatal("User with password should return true for HasPassword()")
	}

	// User without password
	userWithoutPassword := db.User{
		HashedPassword: nil,
	}
	if userWithoutPassword.HasPassword() {
		t.Fatal("User without password should return false for HasPassword()")
	}

	// User with empty password string
	emptyPassword := ""
	userWithEmptyPassword := db.User{
		HashedPassword: &emptyPassword,
	}
	if userWithEmptyPassword.HasPassword() {
		t.Fatal("User with empty password should return false for HasPassword()")
	}
}

// TestUserHasOIDCHelper tests the HasOIDC helper method
func TestUserHasOIDCHelper(t *testing.T) {
	// User with OIDC
	userWithOIDC := db.User{
		OIDCSubject: stringPtr("auth0|123"),
	}
	if !userWithOIDC.HasOIDC() {
		t.Fatal("User with OIDC should return true for HasOIDC()")
	}

	// User without OIDC
	userWithoutOIDC := db.User{
		OIDCSubject: nil,
	}
	if userWithoutOIDC.HasOIDC() {
		t.Fatal("User without OIDC should return false for HasOIDC()")
	}

	// User with empty OIDC subject
	emptySubject := ""
	userWithEmptyOIDC := db.User{
		OIDCSubject: &emptySubject,
	}
	if userWithEmptyOIDC.HasOIDC() {
		t.Fatal("User with empty OIDC subject should return false for HasOIDC()")
	}
}

// TestMixedAuthenticationScenarios tests various combinations of auth methods
func TestMixedAuthenticationScenarios(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	// Scenario 1: Local-only user
	localUserID, err := database.CreateUser("local@example.com", "password123", db.RoleAdmin)
	if err != nil {
		t.Fatalf("Failed to create local user: %s", err)
	}
	localUser, _ := database.GetUser(db.ByUserID(localUserID))
	if !localUser.HasPassword() || localUser.HasOIDC() {
		t.Fatal("Local user should have password but not OIDC")
	}

	// Scenario 2: OIDC-only user
	oidcUser, err := database.CreateOIDCUser("oidc@example.com", "auth0|oidc", db.RoleReadOnly)
	if err != nil {
		t.Fatalf("Failed to create OIDC user: %s", err)
	}
	if oidcUser.HasPassword() || !oidcUser.HasOIDC() {
		t.Fatal("OIDC user should have OIDC but not password")
	}

	// Scenario 3: Local user with password
	hybridUserID, err := database.CreateUser("hybrid@example.com", "password123", db.RoleCertificateManager)
	if err != nil {
		t.Fatalf("Failed to create local user: %s", err)
	}
	hybridUser, _ := database.GetUser(db.ByUserID(hybridUserID))
	if !hybridUser.HasPassword() || hybridUser.HasOIDC() {
		t.Fatal("Local user should have password only")
	}

	// Verify all three users exist
	users, err := database.ListUsers()
	if err != nil {
		t.Fatalf("Failed to list users: %s", err)
	}
	if len(users) != 3 {
		t.Fatalf("Expected 3 users, got %d", len(users))
	}
}

// Helper function to create string pointers for tests
func stringPtr(s string) *string {
	return &s
}

func TestCreateUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin@canonical.com", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}
	_, err = database.CreateUser("admin@canonical.com", "pw456", 1)
	if err == nil {
		t.Fatalf(
			"An error should have been returned when creating a user with a duplicate email.",
		)
	}
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("An error should have been returned when creating a user with a duplicate email.")
	}
	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.GetUser(db.ByUserID(2))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}
	_, err = database.CreateUser("", "pw456", 0)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with an empty email.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an empty email.")
	}
	num, err = database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.CreateUser("newUser", "", 0)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with a nil password.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with a nil password.")
	}
	num, err = database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}
	_, err = database.CreateUser("newUser", "pw456", 32)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with an invalid role ID.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an invalid role ID.")
	}
}

func TestGetUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin@canonical.com", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.GetUser(db.ByUserID(2))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}

	_, err = database.GetUser(db.ByEmail("admin2@canonical.com"))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}
}

func TestUpdateUserPasswordFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	originalPassword := "pw123"
	_, err := database.CreateUser("admin@canonical.com", originalPassword, 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	err = database.UpdateUserPassword(db.ByUserID(2), "pw456")
	if err == nil {
		t.Fatalf("An error should have been returned when updating a non-existent user.")
	}
	retrievedUser, err := database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete GetUser: %s", err)
	}
	if err := hashing.CompareHashAndPassword(*retrievedUser.HashedPassword, originalPassword); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 1 {
		t.Fatalf("The number of users should be 1.")
	}

	err = database.UpdateUserPassword(db.ByUserID(1), "")
	if err == nil {
		t.Fatalf("An error should have been returned when updating a user with an empty password.")
	}
	if !errors.Is(err, db.ErrInvalidInput) {
		t.Fatalf("An ErrInvalidInput should have been returned when updating a user with an empty password.")
	}
	retrievedUser, err = database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete GetUser: %s", err)
	}
	if err := hashing.CompareHashAndPassword(*retrievedUser.HashedPassword, originalPassword); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
}

func TestDeleteUserFails(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)

	_, err := database.CreateUser("admin@canonical.com", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}
	_, err = database.CreateUser("normal", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	err = database.DeleteUser(db.ByUserID(3))
	if err == nil {
		t.Fatalf("An error should have been returned when deleting a non-existent user.")
	}

	num, err := database.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("The number of users should be 2.")
	}
}
