// Package server provides a server object that represents the Notary backend
package server

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/canonical/notary/internal/db"
)

type HandlerConfig struct {
	DB                      *db.Database
	SendPebbleNotifications bool
	JWTSecret               []byte
}

func SendPebbleNotification(key, request_id string) error {
	cmd := exec.Command("pebble", "notify", key, fmt.Sprintf("request_id=%s", request_id))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("couldn't execute a pebble notify: %w", err)
	}
	return nil
}

func generateJWTSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return bytes, nil
}

// New creates an environment and an http server with handlers that Go can start listening to
func New(port int, cert []byte, key []byte, dbPath string, pebbleNotificationsEnabled bool) (*http.Server, error) {
	serverCerts, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	db, err := db.NewDatabase(dbPath)
	if err != nil {
		return nil, err
	}

	jwtSecret, err := generateJWTSecret()
	if err != nil {
		return nil, err
	}
	env := &HandlerConfig{}
	env.DB = db
	env.SendPebbleNotifications = pebbleNotificationsEnabled
	env.JWTSecret = jwtSecret
	router := NewHandler(env)

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", port),

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
