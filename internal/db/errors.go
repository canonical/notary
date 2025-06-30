package db

import (
	"errors"
	"strings"

	"github.com/canonical/sqlair"
)

var (
	ErrNotFound                  = errors.New("resource not found")
	ErrInternal                  = errors.New("internal error")
	ErrInvalidFilter             = errors.New("invalid filter")
	ErrAlreadyExists             = errors.New("resource already exists")
	ErrInvalidInput              = errors.New("invalid input")
	ErrInvalidCertificate        = errors.New("invalid certificate")
	ErrInvalidCertificateRequest = errors.New("invalid certificate request")
	ErrInvalidPrivateKey         = errors.New("invalid private key")
	ErrInvalidUser               = errors.New("invalid user")
)

// IsConstraintError checks if the error is a constraint error
func IsConstraintError(err error, constraint string) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), constraint)
}

func rowFound(err error) bool {
	return err == nil
}

func realError(err error) bool {
	return err != nil && !errors.Is(err, sqlair.ErrNoRows) && !errors.Is(err, ErrNotFound)
}

func HandleDBCreateQueryError(err error, entity_name string) error {

	return nil
}
