package main

import (
	"flag"
	"log"
	"os"

	server "github.com/canonical/gocert/internal/api"
	"github.com/canonical/gocert/internal/config"
)

func main() {
	log.SetOutput(os.Stdout)
	configFilePtr := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePtr == "" {
		log.Fatalf("Providing a config file is required.")
	}
	conf, err := config.Validate(*configFilePtr)
	if err != nil {
		log.Fatalf("Couldn't validate config file: %s", err)
	}
	srv, err := server.NewServer(conf.Port, conf.Cert, conf.Key, conf.DBPath, conf.PebbleNotificationsEnabled)
	if err != nil {
		log.Fatalf("Couldn't create server: %s", err)
	}
	log.Printf("Starting server at %s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server ran into error: %s", err)
	}
}
