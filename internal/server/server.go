// Package server provides a server object that represents the Notary backend
package server

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type HandlerConfig struct {
	DB                      *db.Database
	Logger                  *zap.Logger
	ExternalHostname        string
	JWTSecret               []byte
	SendPebbleNotifications bool
}

type NotificationKey int

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

// This secret should be generated once and stored in the database, encrypted.
func generateJWTSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return bytes, nil
}

// New creates an environment and an http server with handlers that Go can start listening to
func New(port int, cert []byte, key []byte, dbPath string, externalHostname string, pebbleNotificationsEnabled bool, logger *zap.Logger) (*http.Server, error) {
	serverCerts, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	database, err := db.NewDatabase(dbPath)
	if err != nil {
		return nil, err
	}

	// Try to get existing JWT secret from database
	jwtSecret, err := database.GetJWTSecret()
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Generate new JWT secret if none exists
			jwtSecret, err = generateJWTSecret()
			if err != nil {
				return nil, err
			}
			if err := database.StoreJWTSecret(jwtSecret); err != nil {
				return nil, fmt.Errorf("failed to store JWT secret: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get JWT secret: %w", err)
		}
	}

	env := &HandlerConfig{}
	env.DB = database
	env.SendPebbleNotifications = pebbleNotificationsEnabled
	env.JWTSecret = jwtSecret
	env.ExternalHostname = externalHostname
	env.Logger = logger
	router := NewHandler(env)

	stdErrLog, err := zap.NewStdLogAt(logger, zapcore.ErrorLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger for http server: %w", err)
	}

	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		ErrorLog:       stdErrLog,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        router,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCerts},
		},
	}

	return s, nil
}
