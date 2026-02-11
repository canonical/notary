package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/hashing"
)

// ListUsers returns all of the users and their fields available in the database.
func (db *Database) ListUsers() ([]User, error) {
	return ListEntities[User](db, db.stmts.ListUsers)
}

// GetUser retrieves the name, password and the role ID of a user.
func (db *Database) GetUser(filter UserFilter) (*User, error) {
	userRow := filter.AsUser()
	return GetOneEntity[User](db, db.stmts.GetUser, *userRow)
}

// CreateUser creates a new user from a given email, password and role ID.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *Database) CreateUser(email string, password string, roleID RoleID) (int64, error) {
	err := ValidateUser(email, roleID)
	if err != nil {
		return 0, err
	}
	pw, err := hashing.HashPassword(password)
	if err != nil {
		if errors.Is(err, hashing.ErrInvalidPassword) {
			return 0, fmt.Errorf("%w: invalid password", ErrInvalidUser)
		}
		return 0, fmt.Errorf("%w: failed to create user", ErrInternal)
	}

	row := User{
		Email:          email,
		HashedPassword: &pw,
		RoleID:         roleID,
	}
	insertedRowID, err := CreateEntity(db, db.stmts.CreateUser, row)
	if err != nil {
		return 0, err
	}
	return insertedRowID, nil
}

// CreateOIDCUser creates a new user from OIDC login (no password required)
// Email is optional - the oidcSubject is the primary identifier
func (db *Database) CreateOIDCUser(email, oidcSubject string, roleID RoleID) (*User, error) {
	err := ValidateOIDCUser(oidcSubject, roleID)
	if err != nil {
		return nil, err
	}

	row := User{
		Email:          email,
		HashedPassword: nil, // OIDC users don't have passwords
		RoleID:         roleID,
		OIDCSubject:    &oidcSubject,
	}
	insertedRowID, err := CreateEntity(db, db.stmts.CreateOIDCUser, row)
	if err != nil {
		return nil, err
	}

	// Return the created user
	return db.GetUser(ByUserID(insertedRowID))
}

// UpdateUser updates the password of the given user.
// Just like with CreateUser, this function handles hashing and salting the password before storage.
func (db *Database) UpdateUserPassword(filter UserFilter, password string) error {
	userRow := filter.AsUser()
	hashedPassword, err := hashing.HashPassword(password)
	if err != nil {
		if errors.Is(err, hashing.ErrInvalidPassword) {
			return fmt.Errorf("%w: invalid password", ErrInvalidInput)
		}
		return fmt.Errorf("%w: failed to hash password", ErrInternal)
	}
	userRow.HashedPassword = &hashedPassword
	return UpdateEntity(db, db.stmts.UpdateUser, userRow)
}

// UpdateUserRole updates the role_id of the given user.
func (db *Database) UpdateUserRole(filter UserFilter, roleID RoleID) error {
	if roleID < 0 || roleID > 3 {
		return fmt.Errorf("%w: invalid role ID: %d", ErrInvalidInput, roleID)
	}
	userRow := filter.AsUser()
	userRow.RoleID = roleID
	return UpdateEntity(db, db.stmts.UpdateUserRole, userRow)
}

// DeleteUserByID removes a user from the table.
func (db *Database) DeleteUser(filter UserFilter) error {
	userRow := filter.AsUser()
	return DeleteEntity(db, db.stmts.DeleteUser, userRow)
}

// NumUsers returns the number of users in the database.
func (db *Database) NumUsers() (int, error) {
	result := NumUsers{}
	err := db.Conn.Query(context.Background(), db.stmts.GetNumUsers).Get(&result)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to get number of users", ErrInternal)
	}
	return result.Count, nil
}
