package main

import (
	"flag"
	"fmt"
	"os"

	server "github.com/canonical/gocert/api"
	"github.com/canonical/gocert/internal/certdb"
)

func main() {
	configFilePtr := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()

	if *configFilePtr == "" {
		fmt.Fprintf(os.Stderr, "Providing a valid config file is required.")
	}
	config, err := server.ValidateConfigFile(*configFilePtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config file validation failed: %s.", err)
	}
	_, err = certdb.NewCertificateRequestsRepository(config.DBPath, "CertificateRequests")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't connect to database: %s", err)
		os.Exit(1)
	}
	srv, err := server.NewServer(config.Cert, config.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't create server: %s", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintf(os.Stderr, "Server ran into error: %s", err)
		os.Exit(1)
	}
}
