package db

import (
	"context"
	"fmt"

	"github.com/canonical/sqlair"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID int `db:"id"`

	Username       string `db:"username"`
	HashedPassword string `db:"hashed_password"`
	Permissions    int    `db:"permissions"`
}

const queryCreateUsersTable = `
	CREATE TABLE IF NOT EXISTS %s (
 		id INTEGER PRIMARY KEY AUTOINCREMENT,

		username TEXT NOT NULL UNIQUE,
		hashed_password TEXT NOT NULL,
		permissions INTEGER
)`

const (
	listUsersStmt   = "SELECT &User.* from %s"
	getUserStmt     = "SELECT &User.* from %s WHERE id==$User.id or username==$User.username"
	createUserStmt  = "INSERT INTO %s (username, hashed_password, permissions) VALUES ($User.username, $User.hashed_password, $User.permissions)"
	updateUserStmt  = "UPDATE %s SET hashed_password=$User.hashed_password WHERE id==$User.id or username==$User.username"
	deleteUserStmt  = "DELETE FROM %s WHERE id==$User.id"
	getNumUsersStmt = "SELECT COUNT(*) AS &NumUsers.count FROM %s"
)

// ListUsers returns all of the users and their fields available in the database.
func (db *Database) ListUsers() ([]User, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(listUsersStmt, db.usersTable), User{})
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
func (db *Database) GetUserByID(id int) (*User, error) {
	row := User{
		ID: id,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getUserStmt, db.usersTable), User{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&row)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// GetUserByUsername retrieves the id, password and the permission level of a user.
func (db *Database) GetUserByUsername(name string) (*User, error) {
	row := User{
		Username: name,
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(getUserStmt, db.usersTable), User{})
	if err != nil {
		return nil, err
	}
	err = db.conn.Query(context.Background(), stmt, row).Get(&row)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) error {
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(createUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		Username:       username,
		HashedPassword: string(pw),
		Permissions:    permission,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// UpdateUser updates the password of the given user.
// Just like with CreateUser, this function handles hashing and salting the password before storage.
func (db *Database) UpdateUserPassword(id int, password string) error {
	_, err := db.GetUserByID(id)
	if err != nil {
		return err
	}
	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(updateUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		ID:             id,
		HashedPassword: string(pw),
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

// DeleteUserByID removes a user from the table.
func (db *Database) DeleteUserByID(id int) error {
	_, err := db.GetUserByID(id)
	if err != nil {
		return err
	}
	stmt, err := sqlair.Prepare(fmt.Sprintf(deleteUserStmt, db.usersTable), User{})
	if err != nil {
		return err
	}
	row := User{
		ID: id,
	}
	err = db.conn.Query(context.Background(), stmt, row).Run()
	return err
}

type NumUsers struct {
	Count int `db:"count"`
}

// NumUsers returns the number of users in the database.
func (db *Database) NumUsers() (int, error) {
	stmt, err := sqlair.Prepare(fmt.Sprintf(getNumUsersStmt, db.usersTable), NumUsers{})
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
