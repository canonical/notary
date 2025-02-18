package db

import (
	"context"
	"fmt"

	"github.com/canonical/sqlair"
)

type User struct {
	ID int64 `db:"id"`

	Username       string `db:"username"`
	HashedPassword string `db:"hashed_password"`
	Permissions    int    `db:"permissions"`
}

const queryCreateUsersTable = `
	CREATE TABLE IF NOT EXISTS users (
 		id INTEGER PRIMARY KEY AUTOINCREMENT,

		username TEXT NOT NULL UNIQUE 
			CHECK (trim(username) != ''),
		hashed_password TEXT NOT NULL 
			CHECK (trim(hashed_password) != ''),
		permissions INTEGER CHECK (permissions IN (0,1))
)`

const (
	listUsersStmt   = "SELECT &User.* from users"
	getUserStmt     = "SELECT &User.* from users WHERE id==$User.id or username==$User.username"
	createUserStmt  = "INSERT INTO users (username, hashed_password, permissions) VALUES ($User.username, $User.hashed_password, $User.permissions)"
	updateUserStmt  = "UPDATE users SET hashed_password=$User.hashed_password WHERE id==$User.id or username==$User.username"
	deleteUserStmt  = "DELETE FROM users WHERE id==$User.id"
	getNumUsersStmt = "SELECT COUNT(*) AS &NumUsers.count FROM users"
)

// ListUsers returns all of the users and their fields available in the database.
func (db *Database) ListUsers() ([]User, error) {
	stmt, err := sqlair.Prepare(listUsersStmt, User{})
	if err != nil {
		return nil, err
	}
	var users []User
	err = db.conn.Query(context.Background(), stmt).GetAll(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

// GetUserByID retrieves the name, password and the permission level of a user.
func (db *Database) GetUser(filter UserFilter) (*User, error) {
	var userRow User

	switch {
	case filter.ID != nil:
		userRow = User{ID: *filter.ID}
	case filter.Username != nil:
		userRow = User{Username: *filter.Username}
	default:
		return nil, fmt.Errorf("invalid filter: both ID and Username are nil")
	}

	stmt, err := sqlair.Prepare(getUserStmt, User{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, userRow).Get(&userRow)
	if err != nil {
		return nil, err
	}
	return &userRow, nil
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) error {
	pw, err := HashPassword(password)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(createUserStmt, User{})
	if err != nil {
		return err
	}
	row := User{
		Username:       username,
		HashedPassword: pw,
		Permissions:    permission,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// UpdateUser updates the password of the given user.
// Just like with CreateUser, this function handles hashing and salting the password before storage.
func (db *Database) UpdateUserPassword(filter UserFilter, password string) error {
	userRow, err := db.GetUser(filter)
	if err != nil {
		return err
	}
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(updateUserStmt, User{})
	if err != nil {
		return err
	}
	userRow.HashedPassword = hashedPassword
	err = db.conn.Query(context.Background(), stmt, userRow).Run()
	return err
}

// DeleteUserByID removes a user from the table.
func (db *Database) DeleteUser(filter UserFilter) error {
	userRow, err := db.GetUser(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(deleteUserStmt, User{})
	if err != nil {
		return err
	}
	err = db.conn.Query(context.Background(), stmt, userRow).Run()
	return err
}

type NumUsers struct {
	Count int `db:"count"`
}

// NumUsers returns the number of users in the database.
func (db *Database) NumUsers() (int, error) {
	stmt, err := sqlair.Prepare(getNumUsersStmt, NumUsers{})
	if err != nil {
		return 0, err
	}
	result := NumUsers{}
	err = db.conn.Query(context.Background(), stmt).Get(&result)
	if err != nil {
		return 0, err
	}
	return result.Count, nil
}
