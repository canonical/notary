package db

import (
	"context"
	"errors"
	"fmt"
	"log"

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
	return ListEntities[User](db, listUsersStmt)
}

// GetUser retrieves the name, password and the permission level of a user.
func (db *Database) GetUser(filter UserFilter) (*User, error) {
	var userRow User

	switch {
	case filter.ID != nil:
		userRow = User{ID: *filter.ID}
	case filter.Username != nil:
		userRow = User{Username: *filter.Username}
	default:
		return nil, InvalidFilterError("user", "both ID and Username are nil")
	}

	return GetOneEntity(db, getUserStmt, userRow)
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) (int64, error) {
	pw, err := HashPassword(password)
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	stmt, err := sqlair.Prepare(createUserStmt, User{})
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	row := User{
		Username:       username,
		HashedPassword: pw,
		Permissions:    permission,
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), stmt, row).Get(&outcome)
	if err != nil {
		log.Println(err)
		if isUniqueConstraintError(err) {
			return 0, fmt.Errorf("%w: username already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		log.Println(err)
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	return insertedRowID, nil
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
		log.Println(err)
		return fmt.Errorf("%w: failed to hash password", ErrInternal)
	}
	stmt, err := sqlair.Prepare(updateUserStmt, User{})
	if err != nil {
		log.Println(err)
		return fmt.Errorf("%w: failed to prepare update user statement", ErrInternal)
	}
	userRow.HashedPassword = hashedPassword
	err = db.conn.Query(context.Background(), stmt, userRow).Run()
	if err != nil {
		log.Println(err)
		if errors.Is(err, sqlair.ErrNoRows) {
			return fmt.Errorf("%w: user not found", ErrNotFound)
		}
		return fmt.Errorf("%w: failed to update user", ErrInternal)
	}
	return nil
}

// DeleteUserByID removes a user from the table.
func (db *Database) DeleteUser(filter UserFilter) error {
	userRow, err := db.GetUser(filter)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(deleteUserStmt, User{})
	if err != nil {
		return fmt.Errorf("%w: failed to prepare delete user statement", ErrInternal)
	}
	err = db.conn.Query(context.Background(), stmt, userRow).Run()
	if err != nil {
		return fmt.Errorf("%w: failed to delete user", ErrInternal)
	}
	return nil
}

type NumUsers struct {
	Count int `db:"count"`
}

// NumUsers returns the number of users in the database.
func (db *Database) NumUsers() (int, error) {
	stmt, err := sqlair.Prepare(getNumUsersStmt, NumUsers{})
	if err != nil {
		return 0, fmt.Errorf("%w: failed to prepare get number of users statement", ErrInternal)
	}
	result := NumUsers{}
	err = db.conn.Query(context.Background(), stmt).Get(&result)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to get number of users", ErrInternal)
	}
	return result.Count, nil
}
