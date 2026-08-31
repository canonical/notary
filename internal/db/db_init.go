package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/sqlair"
)

// Close closes the sqlair connection and the dqlite node.
func (db *DatabaseRepository) Close() error {
	var first error
	if db.Conn != nil {
		if err := db.Conn.PlainDB().Close(); err != nil {
			first = err
		}
		db.Conn = nil
		db.stmts = nil
	}
	if db.Node != nil {
		if err := db.Node.Close(); err != nil && first == nil {
			first = err
		}
		db.Node = nil
	}
	return first
}

// NewDatabase starts (or resumes) a dqlite node at DatabasePath and wraps it with sqlair.
func NewDatabase(dbOpts *DatabaseOpts) (*DatabaseRepository, error) {
	if dbOpts == nil {
		return nil, errors.New("database options are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var (
		sqlConnection *sql.DB
		node          *cluster.Node
		err           error
	)

	if dbOpts.DatabasePath == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(dbOpts.DatabasePath, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	node, err = cluster.Start(cluster.Options{
		Dir:     dbOpts.DatabasePath,
		Address: dbOpts.Address,
	})
	if err != nil {
		return nil, err
	}
	sqlConnection, err = node.Open(ctx)
	if err != nil {
		_ = node.Close()
		return nil, err
	}

	if _, err := sqlConnection.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		if node != nil {
			_ = sqlConnection.Close()
			_ = node.Close()
		}
		return nil, err
	}

	if err := applySchema(ctx, sqlConnection); err != nil {
		if node != nil {
			_ = sqlConnection.Close()
			_ = node.Close()
		}
		return nil, fmt.Errorf("failed to apply schema updates: %w", err)
	}

	repo := new(DatabaseRepository)
	repo.stmts = PrepareStatements()
	repo.Conn = sqlair.NewDB(sqlConnection)
	repo.Path = dbOpts.DatabasePath
	repo.Node = node
	return repo, nil
}

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *DatabaseRepository, stmt *sqlair.Statement, inputArgs ...any) ([]T, error) {
	var entities []T
	err := db.Conn.Query(context.Background(), stmt, inputArgs...).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, fmt.Errorf("failed to list %s: %w", getTypeName[T](), ErrInternal)
	}
	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, inputArgs ...any) (*T, error) {
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

func CreateEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, new_entity T) (int64, error) {
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

func UpdateEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, updated_entity T) error {
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

func DeleteEntity[T any](db *DatabaseRepository, stmt *sqlair.Statement, entity_to_delete T) error {
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
