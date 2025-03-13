package db

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNotFound      = errors.New("resource not found")
	ErrInternal      = errors.New("internal error")
	ErrInvalidFilter = errors.New("invalid filter")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

func NotFoundError(entityName string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, entityName)
}

// InvalidFilterError creates a more specific invalid filter error
func InvalidFilterError(filterType, message string) error {
	return fmt.Errorf("%w: %s - %s", ErrInvalidFilter, filterType, message)
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isCheckUsernameOrPasswordConstraintError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "CHECK constraint failed: trim")
}

func isCheckPermissionsConstraintError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "CHECK constraint failed: permissions IN (0,1)")
}
