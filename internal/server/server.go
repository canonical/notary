// Package server provides a server object that represents the Notary backend
package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	ReconcileLoopInterval = 1 * time.Hour
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

	jwtSecret, err := setUpJWTSecret(database)
	if err != nil {
		return nil, err
	}

	env := &HandlerConfig{}
	env.DB = database
	env.SendPebbleNotifications = pebbleNotificationsEnabled
	env.JWTSecret = jwtSecret
	env.ExternalHostname = externalHostname
	env.Logger = logger
	router := NewHandler(env)

	// Start periodic CA reconciliation in background
	go func() {
		ticker := time.NewTicker(ReconcileLoopInterval)
		defer ticker.Stop()

		for {
			if err := ReconcileCAStatus(env.DB, env.Logger); err != nil {
				env.Logger.Error("failed to reconcile CA status", zap.Error(err))
			}
			<-ticker.C
		}
	}()

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

// reconcileCAStatus checks the status of all CAs in the database and updates their status
// if necessary.
func ReconcileCAStatus(dbClient *db.Database, logger *zap.Logger) error {
	certificateAuthorities, err := dbClient.ListCertificateAuthorities()
	if err != nil {
		return fmt.Errorf("failed to list certificate authorities: %w", err)
	}

	for _, ca := range certificateAuthorities {
		caDenorm, err := dbClient.GetDenormalizedCertificateAuthority(
			db.ByCertificateAuthorityDenormalizedID(ca.CertificateAuthorityID),
		)
		if err != nil {
			return fmt.Errorf("failed to get denormalized certificate authority: %w", err)
		}

		certPEM := []byte(caDenorm.CertificateChain)

		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			logger.Warn("failed to parse PEM block as certificate", zap.Int64("ca_id", ca.CertificateAuthorityID))
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Warn("failed to parse certificate", zap.Int64("ca_id", ca.CertificateAuthorityID), zap.Error(err))
			continue
		}

		if time.Now().After(cert.NotAfter) && ca.Status != db.CAExpired {
			err = dbClient.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CAExpired)
			if err != nil {
				return fmt.Errorf("failed to update CA status to expired: %w", err)
			}
			logger.Info("updated CA status to expired", zap.Int64("ca_id", ca.CertificateAuthorityID))
		}
	}

	return nil
}
