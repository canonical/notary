package server

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
)

// generateSKI generates the Subject Key Identifier (SKI) for the given private key.
// The SKI is the SHA-1 hash of the public key.
// The SKI is used to identify the public key in the certificate and is used in the Authority Key Identifier extension.
// The SKI is necessary for CRL signing.
func generateSKI(priv *rsa.PrivateKey) ([]byte, error) {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	var spki struct {
		_                asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	asn1.Unmarshal(pubKeyBytes, &spki)
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hash[:], nil
}
