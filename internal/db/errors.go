package db

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNotFound                  = errors.New("resource not found")
	ErrInternal                  = errors.New("internal error")
	ErrInvalidFilter             = errors.New("invalid filter")
	ErrAlreadyExists             = errors.New("resource already exists")
	ErrInvalidInput              = errors.New("invalid input")
	ErrInvalidCertificate        = errors.New("invalid certificate")
	ErrInvalidCertificateRequest = errors.New("invalid certificate request")
)

// NotFoundError customizes the error message for not found errors
func NotFoundError(entityName string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, entityName)
}

// InvalidFilterError customizes the error message for invalid filter errors
func InvalidFilterError(filterType, message string) error {
	return fmt.Errorf("%w: %s - %s", ErrInvalidFilter, filterType, message)
}

// IsConstraintError checks if the error is a constraint error
func IsConstraintError(err error, constraint string) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), constraint)
}
