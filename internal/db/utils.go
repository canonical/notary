package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/sqlair"
)

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *Database, query string) ([]T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, fmt.Errorf("%w: error compiling sql query", ErrInternal)
	}

	var entities []T
	err = db.conn.Query(context.Background(), stmt).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, ErrInternal
	}

	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *Database, query string, params T) (*T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, fmt.Errorf("%w: error compiling sql query", ErrInternal)
	}

	var result T
	err = db.conn.Query(context.Background(), stmt, params).Get(&result)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, ErrInternal
	}

	return &result, nil
}
