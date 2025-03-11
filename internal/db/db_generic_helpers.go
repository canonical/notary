package db

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/canonical/sqlair"
)

// ListEntities is a generic function to retrieve all entities of a given type from the database.
func ListEntities[T any](db *Database, query string) ([]T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("failed to list entities: %w", ErrInternal)
	}
	var entities []T
	err = db.conn.Query(context.Background(), stmt).GetAll(&entities)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return entities, nil
		}
		log.Println(err)
		return nil, fmt.Errorf("failed to list entities: %w", ErrInternal)
	}
	return entities, nil
}

// GetOneEntity is a generic function to execute a database query and get a single entity.
// It handles preparing the statement, executing the query, and error handling.
func GetOneEntity[T any](db *Database, query string, params T) (*T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to prepare query", ErrInternal)
	}

	var result T
	err = db.conn.Query(context.Background(), stmt, params).Get(&result)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, ErrNotFound
		}
		log.Println(err)
		return nil, fmt.Errorf("%w: failed to execute query", ErrInternal)
	}

	return &result, nil
}
