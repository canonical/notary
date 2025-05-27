package db_test

import (
	"errors"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/hashing"
)

func TestUsersEndToEnd(t *testing.T) {
	database, err := db.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	userID, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	if userID != 1 {
		t.Fatalf("Couldn't complete Create: expected user id 1, but got %d", userID)
	}

	userID, err = database.CreateUser("norman", "pw456", 0)
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

	retrievedUser, err := database.GetUser(db.ByUsername("admin"))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}

	retrievedUser, err = database.GetUser(db.ByUserID(1))
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, "pw123"); err != nil {
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
	retrievedUser, _ = database.GetUser(db.ByUsername("norman"))
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, "thebestpassword"); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}

func TestCreateUserFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	_, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}
	_, err = database.CreateUser("admin", "pw456", 1)
	if err == nil {
		t.Fatalf(
			"An error should have been returned when creating a user with a duplicate username.",
		)
	}
	if !errors.Is(err, db.ErrAlreadyExists) {
		t.Fatalf("An error should have been returned when creating a user with a duplicate username.")
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
		t.Fatalf("An error should have been returned when creating a user with an empty username.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an empty username.")
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
	_, err = database.CreateUser("newUser", "pw456", 2)
	if err == nil {
		t.Fatalf("An error should have been returned when creating a user with an invalid permission level.")
	}
	if !errors.Is(err, db.ErrInvalidUser) {
		t.Fatalf("An ErrInvalidUser should have been returned when creating a user with an invalid permission level.")
	}
}

func TestGetUserFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	_, err := database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete CreateUser: %s", err)
	}

	_, err = database.GetUser(db.ByUserID(2))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}

	_, err = database.GetUser(db.ByUsername("admin2"))
	if err == nil {
		t.Fatalf("An error should have been returned when getting a non-existent user.")
	}
}

func TestUpdateUserPasswordFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()
	originalPassword := "pw123"
	_, err := database.CreateUser("admin", originalPassword, 1)
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
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, originalPassword); err != nil {
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
	if err := hashing.CompareHashAndPassword(retrievedUser.HashedPassword, originalPassword); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
}

func TestDeleteUserFails(t *testing.T) {
	database, _ := db.NewDatabase(":memory:")
	defer database.Close()

	_, err := database.CreateUser("admin", "pw123", 1)
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
