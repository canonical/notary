// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/canonical/gocert/internal/certdb"
	"gopkg.in/yaml.v3"
)

type ConfigYAML struct {
	KeyPath  string `yaml:"KeyPath"`
	CertPath string `yaml:"CertPath"`
	DBPath   string `yaml:"DBPath"`
	Port     int    `yaml:"Port"`
}

type Config struct {
	Key    []byte
	Cert   []byte
	DBPath string
	Port   int
}

type Environment struct {
	DB *certdb.CertificateRequestsRepository
}

// validateConfigFile opens and processes the given yaml file, and catches errors in the process
func validateConfigFile(filePath string) (Config, error) {
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
	dbfile, err := os.OpenFile(c.DBPath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	err = dbfile.Close()
	if err != nil {
		return config, errors.Join(validationErr, err)
	}

	config.Cert = cert
	config.Key = key
	config.DBPath = c.DBPath
	config.Port = c.Port
	return config, nil
}

// NewServer creates an environment and an http server with handlers that Go can start listening to
func NewServer(configFile string) (*http.Server, error) {
	config, err := validateConfigFile(configFile)
	if err != nil {
		return nil, err
	}
	serverCerts, err := tls.X509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, err
	}
	db, err := certdb.NewCertificateRequestsRepository(config.DBPath, "CertificateRequests")
	if err != nil {
		log.Fatalf("Couldn't connect to database: %s", err)
	}

	env := &Environment{}
	env.DB = db
	router := NewGoCertRouter(env)

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", config.Port),

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
