// Package db provides a simplistic ORM to communicate with an SQL database for storage
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/canonical/sqlair"
	_ "github.com/mattn/go-sqlite3"
)

// Close closes the connection to the repository cleanly.
func (db *Database) Close() error {
	if db.Conn == nil {
		return nil
	}
	if err := db.Conn.PlainDB().Close(); err != nil {
		return err
	}
	db.stmts = nil
	return nil
}

// NewDatabase connects to a given table in a given database,
// stores the connection information and returns an object containing the information.
// The database path must be a valid file path or ":memory:".
// The table will be created if it doesn't exist in the format expected by the package.
func NewDatabase(dbOpts *DatabaseOpts) (*Database, error) {
	sqlConnection, err := sql.Open("sqlite3", dbOpts.DatabasePath)
	if err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateCertificateRequestsTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateCertificatesTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateUsersTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreatePrivateKeysTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateCertificateAuthoritiesTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateEncryptionKeysTable); err != nil {
		return nil, err
	}
	if _, err := sqlConnection.Exec(QueryCreateJWTSecretTable); err != nil {
		return nil, err
	}
	db := new(Database)
	db.stmts = PrepareStatements()
	db.Conn = sqlair.NewDB(sqlConnection)

	db.EncryptionKey, err = setUpEncryptionKey(db, dbOpts.Backend, dbOpts.Logger)
	if err != nil {
		return nil, err
	}
	db.JWTSecret, err = setUpJWTSecret(db)
	if err != nil {
		return nil, fmt.Errorf("failed to set up JWT secret: %w", err)
	}

	return db, nil
}

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *Database, stmt *sqlair.Statement, inputArgs ...any) ([]T, error) {
	var entities []T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, fmt.Errorf("failed to list %s: %w", getTypeName[T](), ErrInternal)
	}
	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *Database, stmt *sqlair.Statement, inputArgs ...any) (*T, error) {
	var result T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).Get(&result)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, fmt.Errorf("failed to get %s: %w", getTypeName[T](), ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get %s: %w", getTypeName[T](), ErrInternal)
	}

	return &result, nil
}

func CreateEntity[T any](db *Database, stmt *sqlair.Statement, new_entity T) (int64, error) {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, new_entity).Get(&outcome)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrAlreadyExists)
		}
		return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrInternal)
	}
	insertedRowID, err := outcome.Result().LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %w", getTypeName[T](), ErrInternal)
	}
	return insertedRowID, nil
}

func UpdateEntity[T any](db *Database, stmt *sqlair.Statement, updated_entity T) error {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, updated_entity).Get(&outcome)
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrInternal)
	}
	affectedRows, err := outcome.Result().RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrInternal)
	}
	if affectedRows == 0 {
		return fmt.Errorf("failed to update %s: %w", getTypeName[T](), ErrNotFound)
	}
	return nil
}

func DeleteEntity[T any](db *Database, stmt *sqlair.Statement, entity_to_delete T) error {
	var outcome sqlair.Outcome
	err := db.Conn.Query(context.Background(), stmt, entity_to_delete).Get(&outcome)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrInternal)
	}
	affectedRows, err := outcome.Result().RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrInternal)
	}
	if affectedRows == 0 {
		return fmt.Errorf("failed to delete %s: %w", getTypeName[T](), ErrNotFound)
	}
	return nil
}
