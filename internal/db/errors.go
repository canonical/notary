package db

import (
	"errors"
)

var (
	ErrNotFound                  = errors.New("resource not found")
	ErrInternal                  = errors.New("internal error")
	ErrInvalidFilter             = errors.New("invalid filter")
	ErrAlreadyExists             = errors.New("resource already exists")
	ErrForeignKey                = errors.New("foreign key constraint failed")
	ErrInvalidInput              = errors.New("invalid input")
	ErrInvalidCertificate        = errors.New("invalid certificate")
	ErrInvalidCertificateRequest = errors.New("invalid certificate request")
	ErrInvalidPrivateKey         = errors.New("invalid private key")
	ErrInvalidUser               = errors.New("invalid user")
)

// When a row doesn't exist, an ErrNotFound error is returned.
// Sometimes, we specifically get a row to check if it exists.
// This function returns true if the row was found, which means ErrNotFound was not returned.
func rowFound(err error) bool {
	return err == nil
}

// When a row doesn't exists, an ErrNotFound error is returned.
// Sometimes, we specifically get a row to check if it exists.
// This function makes sure that the error we got was an actual error, and not ErrNotFound,
// which is the expected error to be returned.
func realError(err error) bool {
	return err != nil && !errors.Is(err, ErrNotFound)
}
