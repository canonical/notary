package db

import (
	"errors"
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

// IsConstraintError checks if the error is a constraint error
func IsConstraintError(err error, constraint string) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), constraint)
}
