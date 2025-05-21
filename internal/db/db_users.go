package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/hashing"
	"github.com/canonical/sqlair"
)

// ListUsers returns all of the users and their fields available in the database.
func (db *Database) ListUsers() ([]User, error) {
	users, err := ListEntities[User](db, db.stmts.ListUsers)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list users", err)
	}
	return users, nil
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
		return nil, fmt.Errorf("%w: user - both ID and Username are nil", ErrInvalidFilter)
	}

	user, err := GetOneEntity(db, db.stmts.GetUser, userRow)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, "user")
		}
		return nil, fmt.Errorf("%w: failed to get user", err)
	}

	return user, nil
}

// CreateUser creates a new user from a given username, password and permission level.
// The permission level 1 represents an admin, and a 0 represents a regular user.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(username string, password string, permission int) (int64, error) {
	pw, err := hashing.HashPassword(password)
	if err != nil {
		if errors.Is(err, hashing.ErrInvalidPassword) {
			return 0, fmt.Errorf("%w: invalid password", ErrInvalidInput)
		}
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	row := User{
		Username:       username,
		HashedPassword: pw,
		Permissions:    permission,
	}
	err = ValidateUser(row)
	if err != nil {
		return 0, fmt.Errorf("%w: %e", ErrInvalidInput, err)
	}
	var outcome sqlair.Outcome
	err = db.conn.Query(context.Background(), db.stmts.CreateUser, row).Get(&outcome)
	if err != nil {
		if IsConstraintError(err, "UNIQUE constraint failed") {
			return 0, fmt.Errorf("%w: username already exists", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
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
	hashedPassword, err := hashing.HashPassword(password)
	if err != nil {
		if errors.Is(err, hashing.ErrInvalidPassword) {
			return fmt.Errorf("%w: invalid password", ErrInvalidInput)
		}
		return fmt.Errorf("%w: failed to hash password", ErrInternal)
	}
	userRow.HashedPassword = hashedPassword
	err = db.conn.Query(context.Background(), db.stmts.UpdateUser, userRow).Run()
	if err != nil {
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
	err = db.conn.Query(context.Background(), db.stmts.DeleteUser, userRow).Run()
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
	result := NumUsers{}
	err := db.conn.Query(context.Background(), db.stmts.GetNumUsers).Get(&result)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to get number of users", ErrInternal)
	}
	return result.Count, nil
}
