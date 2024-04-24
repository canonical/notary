package main

import (
	"flag"
	"log"
	"os"

	server "github.com/canonical/gocert/internal/api"
)

func main() {
	log.SetOutput(os.Stderr)
	configFilePtr := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()

	if *configFilePtr == "" {
		log.Fatalf("Providing a valid config file is required.")
	}
	srv, err := server.NewServer(*configFilePtr)
	if err != nil {
		log.Fatalf("Couldn't create server: %s", err)
	}
	log.Printf("Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server ran into error: %s", err)
	}
}
