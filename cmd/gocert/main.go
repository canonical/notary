package main

import (
	"fmt"

	"github.com/canonical/gocert/internal/certdb"
)

var db *certdb.CertificateRequests

func main() {
	db = new(certdb.CertificateRequests)
	if err := db.Connect("./certs.db", "CertificateRequests"); err != nil {
		fmt.Println(err)
	}
	defer db.Disconnect()

	// ListenAndServe
}
