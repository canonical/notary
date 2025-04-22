package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/logger"
	"github.com/canonical/notary/internal/server"
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
	l, err := logger.NewLogger(&conf.Logging)
	if err != nil {
		l.Fatalf("Couldn't create logger: %s", err)
	}
	srv, err := server.New(conf.Port, conf.Cert, conf.Key, conf.DBPath, conf.ExternalHostname, conf.PebbleNotificationsEnabled, l)
	if err != nil {
		l.Fatalf("Couldn't create server: %s", err)
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		l.Infof("Interrupt signal received")
		if err := srv.Shutdown(context.Background()); err != nil {
			l.Errorf("HTTP server Shutdown error: %v", err)
		}
		close(idleConnsClosed)
	}()

	l.Infof("Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		l.Fatalf("HTTP server ListenAndServe: %v", err)
	}
	l.Infof("Shutting down server")
	<-idleConnsClosed
}
