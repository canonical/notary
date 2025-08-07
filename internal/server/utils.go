package server

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os/exec"
)
const (
	CertificateUpdate NotificationKey = 1
)

func (key NotificationKey) String() (string, error) {
	if key == CertificateUpdate {
		return "canonical.com/notary/certificate/update", nil
	}
	return "", fmt.Errorf("unknown notification key: %d", key)
}

func SendPebbleNotification(key NotificationKey, request_id int64) error {
	keyStr, err := key.String()
	if err != nil {
		return fmt.Errorf("couldn't get a string representation of the notification key: %w", err)
	}
	cmd := exec.Command("pebble", "notify", keyStr, fmt.Sprintf("request_id=%v", request_id)) // #nosec: G204
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("couldn't execute a pebble notify: %w", err)
	}
	return nil
}

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

