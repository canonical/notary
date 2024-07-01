package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"

	metrics "github.com/canonical/gocert/internal/metrics"
	"github.com/canonical/gocert/ui"
)

// NewGoCertRouter takes in an environment struct, passes it along to any handlers that will need
// access to it, and takes an http.Handler that will be used to handle metrics.
// then builds and returns it for a server to consume
func NewGoCertRouter(env *Environment) http.Handler {
	apiV1Router := http.NewServeMux()
	apiV1Router.HandleFunc("GET /certificate_requests", GetCertificateRequests(env))
	apiV1Router.HandleFunc("POST /certificate_requests", PostCertificateRequest(env))
	apiV1Router.HandleFunc("GET /certificate_requests/{id}", GetCertificateRequest(env))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}", DeleteCertificateRequest(env))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate", PostCertificate(env))
	apiV1Router.HandleFunc("POST /certificate_requests/{id}/certificate/reject", RejectCertificate(env))
	apiV1Router.HandleFunc("DELETE /certificate_requests/{id}/certificate", DeleteCertificate(env))

	m := metrics.NewMetricsSubsystem(env.DB)
	frontendHandler := newFrontendFileServer()

	router := http.NewServeMux()
	router.HandleFunc("/status", HealthCheck)
	router.Handle("/metrics", m.Handler)
	router.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1Router))
	router.Handle("/", frontendHandler)

	ctx := middlewareContext{metrics: m}
	middleware := createMiddlewareStack(
		metricsMiddleware(&ctx),
		loggingMiddleware(&ctx),
	)
	return middleware(router)
}

// newFrontendFileServer uses the embedded ui output files as the base for a file server
func newFrontendFileServer() http.Handler {
	frontendFS, err := fs.Sub(ui.FrontendFS, "out")
	if err != nil {
		log.Fatal(err)
	}

	fileServer := http.FileServer(http.FS(frontendFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/") || path == "/" {
			path = "/certificate_requests.html"
		} else if !strings.Contains(path, ".") {
			path += ".html"
		}
		r.URL.Path = path
		fileServer.ServeHTTP(w, r)
	})
}

// the health check endpoint simply returns a http.StatusOK
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK) //nolint:errcheck
}

// GetCertificateRequests returns all of the Certificate Requests
func GetCertificateRequests(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certs, err := env.DB.RetrieveAllCSRs()
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		body, err := json.Marshal(certs)
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		if _, err := w.Write(body); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// PostCertificateRequest creates a new Certificate Request, and returns the id of the created row
func PostCertificateRequest(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csr, err := io.ReadAll(r.Body)
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		id, err := env.DB.CreateCSR(string(csr))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				logErrorAndWriteResponse("given csr already recorded", http.StatusBadRequest, w)
				return
			}
			if strings.Contains(err.Error(), "csr validation failed") {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(strconv.FormatInt(id, 10))); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// GetCertificateRequests receives an id as a path parameter, and
// returns the corresponding Certificate Request
func GetCertificateRequest(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		cert, err := env.DB.RetrieveCSR(id)
		if err != nil {
			if err.Error() == "csr id not found" {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		body, err := json.Marshal(cert)
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		if _, err := w.Write(body); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// DeleteCertificateRequest handler receives an id as a path parameter,
// deletes the corresponding Certificate Request, and returns a http.StatusNoContent on success
func DeleteCertificateRequest(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.DeleteCSR(id)
		if err != nil {
			if err.Error() == "csr id not found" {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(strconv.FormatInt(insertId, 10))); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// PostCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func PostCertificate(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cert, err := io.ReadAll(r.Body)
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
			return
		}
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, string(cert))
		if err != nil {
			if err.Error() == "csr id not found" ||
				err.Error() == "certificate does not match CSR" ||
				strings.Contains(err.Error(), "cert validation failed") {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("gocert.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

func RejectCertificate(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, "rejected")
		if err != nil {
			if err.Error() == "csr id not found" {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("gocert.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// DeleteCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func DeleteCertificate(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, "")
		if err != nil {
			if err.Error() == "csr id not found" {
				logErrorAndWriteResponse(err.Error(), http.StatusBadRequest, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("gocert.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// logErrorAndWriteResponse is a helper function that logs any error and writes it back as an http response
func logErrorAndWriteResponse(msg string, status int, w http.ResponseWriter) {
	errMsg := fmt.Sprintf("error: %s", msg)
	log.Println(errMsg)
	w.WriteHeader(status)
	if _, err := w.Write([]byte(errMsg)); err != nil {
		logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
	}
}
