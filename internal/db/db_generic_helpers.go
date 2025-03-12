package db

import (
	"context"
	"errors"

	"github.com/canonical/sqlair"
)

// ListEntities is a generic function that retrieves all entities of a given type.
func ListEntities[T any](db *Database, query string) ([]T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, err
	}

	var entities []T
	err = db.conn.Query(context.Background(), stmt).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, err
	}

	return entities, nil
}

// GetOneEntity executes a database query and gets a single entity.
func GetOneEntity[T any](db *Database, query string, params T) (*T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, err
	}

	var result T
	err = db.conn.Query(context.Background(), stmt, params).Get(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
