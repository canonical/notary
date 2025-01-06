package db_test

import (
	"testing"

	"github.com/canonical/notary/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func TestUsersEndToEnd(t *testing.T) {
	database, err := db.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	err = database.CreateUser("admin", "pw123", 1)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
	}
	err = database.CreateUser("norman", "pw456", 0)
	if err != nil {
		t.Fatalf("Couldn't complete Create: %s", err)
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
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("pw123")); err != nil {
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
	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.HashedPassword), []byte("thebestpassword")); err != nil {
		t.Fatalf("The new password that was given does not match the password that was stored.")
	}
}
