package server

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"strings"

	"github.com/canonical/notary/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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

// VerifyIDToken verifies that an *oauth2.Token is a valid *oidc.IDToken.
func VerifyIDToken(ctx context.Context, appOIDCConfig *config.OIDCConfig, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: appOIDCConfig.OIDCConfig.ClientID,
	}

	return appOIDCConfig.Provider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var result strings.Builder
	for i := 0; i < length; i++ {
		result.WriteByte(charset[rand.Intn(len(charset))])
	}
	return result.String()
}
