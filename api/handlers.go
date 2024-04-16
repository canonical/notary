package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// GoCertRouter takes in an environment struct, passes it along to any handlers that will need
// access to it, then builds and returns it for a server to consume
func GoCertRouter(env *environment) http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("GET /certificate_requests", GetCertificateRequests(env))
	router.HandleFunc("POST /certificate_requests", PostCertificateRequest(env))
	router.HandleFunc("GET /certificate_requests/{id}", GetCertificateRequest(env))
	router.HandleFunc("DELETE /certificate_requests/{id}", DeleteCertificateRequest(env))
	router.HandleFunc("POST /certificate_requests/{id}/certificate", PostCertificate(env))

	v1 := http.NewServeMux()
	v1.HandleFunc("GET /status", HealthCheck)
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", router))

	return Logging(v1)
}

// the health check endpoint simply returns a 200
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200) //nolint:errcheck
}

// GetCertificateRequests returns all of the Certificate Requests
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

// PostCertificateRequest creates a new Certificate Request, and returns the id of the created row
func PostCertificateRequest(env *environment) http.HandlerFunc {
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

// GetCertificateRequests receives an id as a path parameter, and
// returns the corresponding Certificate Request
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

// DeleteCertificateRequest handler receives an id as a path parameter,
// deletes the corresponding Certificate Request, and returns a 204 on success
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

// PostCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
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

// The Logging middleware captures any http request coming through, and logs it
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Println(r.Method, r.URL.Path)
	})
}

// logError is a helper function that logs any error and writes it back as an http response
func logError(msg string, status int, w http.ResponseWriter) {
	errMsg := fmt.Sprintf("error: %s", msg)
	log.Println(errMsg)
	w.WriteHeader(status)
	w.Write([]byte(errMsg))
}
