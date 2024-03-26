package main

import (
	"log"

	"github.com/canonical/gocert/internal/certdb"
)

func main() {
	db := new(certdb.CertificateRequests)
	if err := db.Connect(); err != nil {
		log.Fatal(err)
	}
	defer db.Disconnect()

	// Serve server
}
