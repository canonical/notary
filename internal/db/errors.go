package db

import (
	"errors"
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

// When a row doesn't exist, an ErrNotFound error is returned.
// This function checks if the error is empty, which implies that ErrNotFound was returned.
func rowFound(err error) bool {
	return err == nil
}

func realError(err error) bool {
	return err != nil && !errors.Is(err, ErrNotFound)
}
