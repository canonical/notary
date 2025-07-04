package server

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/db"
)

// generateSKI generates the Subject Key Identifier (SKI) for the given private key.
// The SKI is the SHA-1 hash of the public key.
// The SKI is used to identify the public key in the certificate and is used in the Authority Key Identifier extension.
// The SKI is necessary for CRL signing.
func generateSKI(priv *rsa.PrivateKey) []byte {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(errors.Join(errors.New("failed to generate an SKI for public key"), err))
	}
	var spki struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubKeyBytes, &spki)
	if err != nil {
		panic(errors.Join(errors.New("failed to generate an SKI for public key"), err))
	}
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hash[:]
}

func setUpJWTSecret(database *db.Database) ([]byte, error) {
	jwtSecret, err := database.GetJWTSecret()
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Generate new JWT secret if none exists
			jwtSecret, err = generateJWTSecret()
			if err != nil {
				return nil, err
			}
			if err := database.CreateJWTSecret(jwtSecret); err != nil {
				return nil, fmt.Errorf("failed to store JWT secret: %w", err)
			}
			return jwtSecret, nil
		} else {
			return nil, fmt.Errorf("failed to get JWT secret: %w", err)
		}
	}
	return jwtSecret, nil
}
