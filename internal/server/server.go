// Package server provides a server object that represents the Notary backend
package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type HandlerConfig struct {
	DB                      *db.Database
	SystemLogger            *zap.Logger
	AuditLogger             *logging.AuditLogger
	ExternalHostname        string
	JWTSecret               []byte
	SendPebbleNotifications bool
	PublicConfig            config.PublicConfigData
}

// New creates an environment and an http server with handlers that Go can start listening to
func New(opts *ServerOpts) (*Server, error) {
	serverCerts, err := tls.X509KeyPair(opts.TLSCertificate, opts.TLSPrivateKey)
	if err != nil {
		return nil, err
	}
	stdErrLog, err := zap.NewStdLogAt(opts.SystemLogger, zapcore.ErrorLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger for http server: %w", err)
	}

	cfg := &HandlerConfig{}
	cfg.SendPebbleNotifications = opts.EnablePebbleNotifications
	cfg.JWTSecret = opts.Database.JWTSecret
	cfg.ExternalHostname = opts.ExternalHostname
	cfg.SystemLogger = opts.SystemLogger
	cfg.AuditLogger = logging.NewAuditLogger(opts.AuditLogger)
	cfg.PublicConfig = *opts.PublicConfig
	cfg.DB = opts.Database

	router := NewRouter(cfg)
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", opts.Port),
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
	return &Server{
		Server: s,
	}, err
}

func (s *Server) Start() error {
	return s.ListenAndServeTLS("", "")
}
