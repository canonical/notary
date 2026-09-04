package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const joinTokenTTL = 3 * time.Hour

// JoinToken is the payload inside a `notary cluster add` token.
// It is a one-time join ticket (name, addresses, secret, expiry) plus a TLS
// fingerprint used to pin the HTTPS server that will hand over cluster TLS.
// It does not contain the cluster private key.
type JoinToken struct {
	ServerName  string    `json:"server_name"`
	Fingerprint string    `json:"fingerprint"`
	Addresses   []string  `json:"addresses"`
	Secret      string    `json:"secret"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func newJoinSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encodeJoinToken(t JoinToken) (string, error) {
	body, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(body), nil
}

// DecodeJoinToken parses a token from `notary cluster add`.
func DecodeJoinToken(s string) (JoinToken, error) {
	var t JoinToken
	if s == "" {
		return t, fmt.Errorf("join token is empty")
	}
	body, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return t, fmt.Errorf("decode join token: %w", err)
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return t, fmt.Errorf("parse join token: %w", err)
	}
	if t.ServerName == "" || len(t.Addresses) == 0 || t.Secret == "" || t.Fingerprint == "" {
		return t, fmt.Errorf("join token is missing fields")
	}
	return t, nil
}
