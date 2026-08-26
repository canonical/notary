package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/utils"
)

// ListUsers returns all of the users and their fields available in the database.
func (db *DatabaseRepository) ListUsers() ([]User, error) {
	return ListEntities[User](db, db.stmts.ListUsers)
}

// GetUser retrieves the name, password and the role ID of a user.
func (db *DatabaseRepository) GetUser(filter UserFilter) (*User, error) {
	userRow := filter.AsUser()
	if userRow.OIDCIssuer != nil && userRow.OIDCSubject != nil {
		user, err := GetOneEntity[User](db, db.stmts.GetUserByOIDCIdentity, *userRow)
		if err == nil || !errors.Is(err, ErrNotFound) {
			return user, err
		}
		return db.adoptLegacyOIDCUser(*userRow)
	}
	return GetOneEntity[User](db, db.stmts.GetUser, *userRow)
}

// adoptLegacyOIDCUser claims a user that was created before OIDC identity became
// (issuer, subject).
//
// Those rows carry a NULL issuer, so no lookup matches them and the login would
// try to create a second user for an email that is already taken — locking the
// operator out of their own account. Notary configures one OIDC provider, so the
// issuer such a row must have had is the one presenting itself now.
func (db *DatabaseRepository) adoptLegacyOIDCUser(userRow User) (*User, error) {
	legacy, err := GetOneEntity[User](db, db.stmts.GetUserByLegacyOIDCSubject, userRow)
	if err != nil {
		// ErrNotFound here means what it says: nobody by that subject, so the
		// caller goes on to create one.
		return nil, err
	}

	legacy.OIDCIssuer = userRow.OIDCIssuer
	if err := UpdateEntity[User](db, db.stmts.AdoptOIDCIssuer, *legacy); err != nil {
		return nil, err
	}

	return legacy, nil
}

// CreateUser creates a new user from a given email, password and role ID.
// The password passed in should be in plaintext. This function handles hashing and salting the password before storing it in the database.
func (db *DatabaseRepository) CreateUser(email string, password string, roleID RoleID) (int64, error) {
	err := ValidateUser(email, roleID)
	if err != nil {
		return 0, err
	}
	pw, err := utils.HashPassword(password)
	if err != nil {
		if errors.Is(err, utils.ErrInvalidPassword) {
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
// Email is optional - the (issuer, subject) pair is the primary identifier
func (db *DatabaseRepository) CreateOIDCUser(email, oidcIssuer, oidcSubject string, roleID RoleID) (*User, error) {
	err := ValidateOIDCUser(oidcIssuer, oidcSubject, roleID)
	if err != nil {
		return nil, err
	}

	row := User{
		Email:          email,
		HashedPassword: nil, // OIDC users don't have passwords
		RoleID:         roleID,
		OIDCIssuer:     &oidcIssuer,
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
func (db *DatabaseRepository) UpdateUserPassword(filter UserFilter, password string) error {
	userRow := filter.AsUser()
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		if errors.Is(err, utils.ErrInvalidPassword) {
			return fmt.Errorf("%w: invalid password", ErrInvalidInput)
		}
		return fmt.Errorf("%w: failed to hash password", ErrInternal)
	}
	userRow.HashedPassword = &hashedPassword
	return UpdateEntity(db, db.stmts.UpdateUser, userRow)
}

// UpdateUserRole updates the role_id of the given user.
func (db *DatabaseRepository) UpdateUserRole(filter UserFilter, roleID RoleID) error {
	userRow := filter.AsUser()
	userRow.RoleID = roleID
	return UpdateEntity(db, db.stmts.UpdateUserRole, userRow)
}

// DeleteUserByID removes a user from the table.
func (db *DatabaseRepository) DeleteUser(filter UserFilter) error {
	userRow := filter.AsUser()
	return DeleteEntity(db, db.stmts.DeleteUser, userRow)
}

// NumUsers returns the number of users in the database.
func (db *DatabaseRepository) NumUsers() (int, error) {
	result := NumUsers{}
	err := db.Conn.Query(context.Background(), db.stmts.GetNumUsers).Get(&result)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to get number of users", ErrInternal)
	}
	return result.Count, nil
}
