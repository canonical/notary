// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ConfigYAML struct {
	KeyPath  string
	CertPath string
	DBPath   string
	Port     int
}

type Config struct {
	Key    []byte
	Cert   []byte
	DBPath string
	Port   int
}

func ValidateConfigFile(filePath string) (Config, error) {
	validationErr := errors.New("config file validation failed: ")
	config := Config{}
	configYaml, err := os.ReadFile(filePath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	c := ConfigYAML{}
	if err := yaml.Unmarshal(configYaml, &c); err != nil {
		return config, errors.Join(validationErr, err)
	}
	cert, err := os.ReadFile(c.CertPath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	key, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	if _, err := os.OpenFile(c.DBPath, os.O_CREATE|os.O_RDONLY, 0644); err != nil {
		return config, errors.Join(validationErr, err)
	}
	config.Cert = cert
	config.Key = key
	config.DBPath = c.DBPath
	config.Port = c.Port
	return config, nil
}

// NewServer creates a new http server with handlers that Go can start listening to
func NewServer(certificate, key []byte, port int) (*http.Server, error) {
	serverCerts, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, err
	}
	router := http.NewServeMux()
	router.HandleFunc("GET /", HealthCheck)

	v1 := http.NewServeMux()
	v1.Handle("/v1/", http.StripPrefix("/v1", router))

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", port),

		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        v1,
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCerts},
		},
	}

	return s, nil
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Server Alive")) //nolint:errcheck
}
