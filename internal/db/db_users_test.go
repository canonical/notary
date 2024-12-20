package db_test

import (
	"testing"

	"github.com/canonical/notary/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func TestUsersEndToEnd(t *testing.T) {
	db, err := db.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer db.Close()

	err = db.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = db.CreateUser("norman", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}

	res, err := db.ListUsers()
	if err != nil {
		t.Fatalf("Couldn't complete RetrieveAll: %s", err)
	}
	if len(res) != 2 {
		t.Fatalf("One or more users weren't found in DB")
	}
	num, err := db.NumUsers()
	if err != nil {
		t.Fatalf("Couldn't complete NumUsers: %s", err)
	}
	if num != 2 {
		t.Fatalf("NumUsers didn't return the correct number of users")
	}
	retrievedUser, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	retrievedUser, err = db.GetUserByID(1)
	if err != nil {
		t.Fatalf("Couldn't complete Retrieve: %s", err)
	}
	if retrievedUser.Username != "admin" {
		t.Fatalf("The user from the database doesn't match the user that was given")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("pw123")); err != nil {
		t.Fatalf("The user's password doesn't match the one stored in the database")
	}
	if err = db.DeleteUserByID(1); err != nil {
		t.Fatalf("Couldn't complete Delete: %s", err)
	}
	res, _ = db.ListUsers()
	if len(res) != 1 {
		t.Fatalf("users weren't deleted from the DB properly")
	}
	err = db.UpdateUserPassword(2, "thebestpassword")
	if err != nil {
		t.Fatalf("Couldn't complete Update: %s", err)
	}
	retrievedUser, _ = db.GetUserByUsername("norman")
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("thebestpassword")); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}
