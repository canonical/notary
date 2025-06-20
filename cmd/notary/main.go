package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/encryption_backend"
	l "github.com/canonical/notary/internal/logger"
	"github.com/canonical/notary/internal/server"
	"go.uber.org/zap"
)

func main() {
	log.SetOutput(os.Stderr)
	configFilePtr := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePtr == "" {
		log.Fatalf("Providing a config file is required.")
	}
	conf, err := config.Validate(*configFilePtr)
	if err != nil {
		log.Fatalf("Couldn't validate config file: %s", err)
	}
	logger, err := l.NewLogger(&conf.Logging)
	if err != nil {
		log.Fatalf("Couldn't create logger: %s", err)
	}
	encryptionBackend, err := createEncryptionBackend(conf.EncryptionBackend, logger)
	if err != nil {
		log.Fatalf("Couldn't create encryption backend: %s", err)
	}
	srv, err := server.New(conf.Port, conf.Cert, conf.Key, conf.DBPath, conf.ExternalHostname, conf.PebbleNotificationsEnabled, logger, encryptionBackend)
	if err != nil {
		logger.Fatal("Couldn't create server", zap.Error(err))
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		logger.Info("Interrupt signal received")
		if err := srv.Shutdown(context.Background()); err != nil {
			logger.Error("HTTP server Shutdown error", zap.Error(err))
		}
		close(idleConnsClosed)
	}()

	logger.Info("Starting server at", zap.String("url", srv.Addr))
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		logger.Fatal("HTTP server ListenAndServe", zap.Error(err))
	}
	logger.Info("Shutting down server")
	<-idleConnsClosed
}

func createEncryptionBackend(backendConfig config.BackendConfig, logger *zap.Logger) (encryption_backend.EncryptionBackend, error) {
	switch backendConfig.Type {
	case config.PKCS11:
		backend, err := encryption_backend.NewPKCS11Backend(backendConfig.PKCS11.LibPath, backendConfig.PKCS11.Pin, *backendConfig.PKCS11.KeyID, logger)
		if err != nil {
			return nil, err
		}
		logger.Info("PKCS11 backend configured")
		return backend, nil
	case config.Vault:
		return nil, errors.New("vault backend is not implemented")
	case config.None:
		return encryption_backend.NoEncryptionBackend{}, nil
	}
	return nil, errors.New("unknown backend type")
}
