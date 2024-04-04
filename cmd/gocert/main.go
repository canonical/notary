package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	server "github.com/canonical/gocert/api"
	"github.com/canonical/gocert/internal/certdb"
)

func main() {
	certPathPtr := flag.String("cert", "", "A path for a certificate file to be used by the webserver")
	keyPathPtr := flag.String("key", "", "The path for a private key for the given certificate")
	dbPathPtr := flag.String("db", ":memory:", "The path of the SQLite database for the repository")
	flag.Parse()

	if *certPathPtr == "" || *keyPathPtr == "" {
		fmt.Fprintf(os.Stderr, "Usage: --cert <path/to/certificate> --key <path/to/key>")
		os.Exit(1)
	}
	_, err := certdb.NewCertificateRequestsRepository(*dbPathPtr, "CertificateRequests")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't connect to database: %s", err)
		os.Exit(1)
	}

	srv, err := server.NewServer(0, *certPathPtr, *keyPathPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't create server: %s", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS(*certPathPtr, *keyPathPtr); err != nil {
		if err == http.ErrServerClosed {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Server ran into error: %s", err)
		os.Exit(1)
	}
}
