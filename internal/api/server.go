// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/canonical/gocert/internal/certdb"
)

type Environment struct {
	DB                      *certdb.CertificateRequestsRepository
	SendPebbleNotifications bool
}

func SendPebbleNotification(key, request_id string) error {
	cmd := exec.Command("pebble", "notify", key, fmt.Sprintf("request_id=%s", request_id))
	if err := cmd.Run(); err != nil {
		return errors.Join(errors.New("couldn't execute a pebble notify: "), err)
	}
	return nil
}

// NewServer creates an environment and an http server with handlers that Go can start listening to
func NewServer(port int, cert []byte, key []byte, dbPath string, pebbleNotificationsEnabled bool) (*http.Server, error) {
	serverCerts, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	db, err := certdb.NewCertificateRequestsRepository(dbPath, "CertificateRequests")
	if err != nil {
		log.Fatalf("Couldn't connect to database: %s", err)
	}

	env := &Environment{}
	env.DB = db
	env.SendPebbleNotifications = pebbleNotificationsEnabled
	router := NewGoCertRouter(env)

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", port),

		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        router,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCerts},
		},
	}

	return s, nil
}
