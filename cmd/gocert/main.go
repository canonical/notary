package main

import (
	"flag"
	"log"
	"os"

	server "github.com/canonical/gocert/api"
	"github.com/canonical/gocert/internal/certdb"
)

func main() {
	log.SetOutput(os.Stderr)
	configFilePtr := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()

	if *configFilePtr == "" {
		log.Fatalf("Providing a valid config file is required.")
	}
	config, err := server.ValidateConfigFile(*configFilePtr)
	if err != nil {
		log.Fatalf("Config file validation failed: %s.", err)
	}
	_, err = certdb.NewCertificateRequestsRepository(config.DBPath, "CertificateRequests")
	if err != nil {
		log.Fatalf("Couldn't connect to database: %s", err)
	}
	srv, err := server.NewServer(config.Cert, config.Key, config.Port)
	if err != nil {
		log.Fatalf("Couldn't create server: %s", err)
	}
	log.Printf("Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server ran into error: %s", err)
	}
}
