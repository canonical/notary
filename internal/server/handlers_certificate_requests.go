package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

// GetCertificateRequests returns all of the Certificate Requests
func GetCertificateRequests(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certs, err := env.DB.RetrieveAllCSRs()
		if err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		body, err := json.Marshal(certs)
		if err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		if _, err := w.Write(body); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// PostCertificateRequest creates a new Certificate Request, and returns the id of the created row
func PostCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csr, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		id, err := env.DB.CreateCSR(string(csr))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				writeError("given csr already recorded", http.StatusBadRequest, w)
				return
			}
			if strings.Contains(err.Error(), "csr validation failed") {
				writeError(err.Error(), http.StatusBadRequest, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(strconv.FormatInt(id, 10))); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// GetCertificateRequests receives an id as a path parameter, and
// returns the corresponding Certificate Request
func GetCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		cert, err := env.DB.RetrieveCSR(id)
		if err != nil {
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(err.Error(), http.StatusNotFound, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		body, err := json.Marshal(cert)
		if err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		if _, err := w.Write(body); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// DeleteCertificateRequest handler receives an id as a path parameter,
// deletes the corresponding Certificate Request, and returns a http.StatusNoContent on success
func DeleteCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.DeleteCSR(id)
		if err != nil {
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(err.Error(), http.StatusNotFound, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(strconv.FormatInt(insertId, 10))); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// PostCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func PostCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cert, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(err.Error(), http.StatusBadRequest, w)
			return
		}
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, string(cert))
		if err != nil {
			if errors.Is(err, db.ErrIdNotFound) ||
				err.Error() == "certificate does not match CSR" ||
				strings.Contains(err.Error(), "cert validation failed") {
				writeError(err.Error(), http.StatusBadRequest, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("notary.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

func RejectCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, "rejected")
		if err != nil {
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(err.Error(), http.StatusNotFound, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("notary.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}

// DeleteCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func DeleteCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, "")
		if err != nil {
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(err.Error(), http.StatusBadRequest, w)
				return
			}
			writeError(err.Error(), http.StatusInternalServerError, w)
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("notary.com/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(insertIdStr)); err != nil {
			writeError(err.Error(), http.StatusInternalServerError, w)
		}
	}
}
