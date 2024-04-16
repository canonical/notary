// Package server provides a server object that represents the GoCert backend
package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/canonical/gocert/internal/certdb"
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

type environment struct {
	db *certdb.CertificateRequestsRepository
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

	env := &environment{}
	env.db = db
	router := http.NewServeMux()
	router.HandleFunc("GET /certificate_requests", GetCertificateRequests(env))
	router.HandleFunc("POST /certificate_requests", PostCertificateRequests(env))
	router.HandleFunc("GET /certificate_requests/{id}", GetCertificateRequest(env))
	router.HandleFunc("DELETE /certificate_requests/{id}", DeleteCertificateRequest(env))
	router.HandleFunc("POST /certificate_requests/{id}/certificate", PostCertificate(env))

	v1 := http.NewServeMux()
	v1.HandleFunc("GET /status", HealthCheck)
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", router))

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", config.Port),

		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		Handler:        Logging(v1),
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

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Println(r.Method, r.URL.Path)
	})
}

func GetCertificateRequests(env *environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certs, err := env.db.RetrieveAll()
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		body, err := json.Marshal(certs)
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		w.Write(body)
	}
}

func PostCertificateRequests(env *environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csr := make([]byte, r.ContentLength)
		bytesRead, err := r.Body.Read(csr)
		if bytesRead != int(r.ContentLength) {
			logError("couldn't read the body completely", 400, w)
			return
		}
		if err.Error() != "EOF" {
			logError(err.Error(), 500, w)
			return
		}
		id, err := env.db.Create(string(csr))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				logError("given csr already recorded", 400, w)
				return
			} else {
				logError(err.Error(), 500, w)
				return
			}
		}
		w.WriteHeader(201)
		w.Write([]byte(strconv.FormatInt(id, 10)))
	}
}

func GetCertificateRequest(env *environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		cert, err := env.db.Retrieve(id)
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		body, err := json.Marshal(cert)
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		w.Write(body)
	}
}

func DeleteCertificateRequest(env *environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := env.db.Delete(id)
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		w.WriteHeader(204)
	}
}

func PostCertificate(env *environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cert := make([]byte, r.ContentLength)
		bytesRead, err := r.Body.Read(cert)
		if bytesRead != int(r.ContentLength) {
			logError("couldn't read the body completely", 400, w)
			return
		}
		if err.Error() != "EOF" {
			logError(err.Error(), 500, w)
			return
		}
		id := r.PathValue("id")
		insertId, err := env.db.Update(id, string(cert))
		if err != nil {
			logError(err.Error(), 500, w)
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(strconv.FormatInt(insertId, 10)))
	}
}

func logError(msg string, status int, w http.ResponseWriter) {
	errMsg := fmt.Sprintf("error: %s", msg)
	log.Println(errMsg)
	w.WriteHeader(status)
	w.Write([]byte(errMsg))
}
