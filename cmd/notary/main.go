package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/canonical/notary/internal/config"
	l "github.com/canonical/notary/internal/logger"
	"github.com/canonical/notary/internal/server"
	"github.com/canonical/notary/internal/trace"
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

	// Set up tracing if enabled
	tracerShutdown, err := trace.SetupTracing(context.Background(), &conf.Tracing, logger)
	if err != nil {
		logger.Fatal("Couldn't set up tracing", zap.Error(err))
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracerShutdown(shutdownCtx); err != nil {
			logger.Error("Failed to shutdown tracer provider", zap.Error(err))
		}
	}()

	srv, err := server.New(conf.Port, conf.Cert, conf.Key, conf.DBPath, conf.ExternalHostname, conf.PebbleNotificationsEnabled, logger, conf.Tracing.Enabled)
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
