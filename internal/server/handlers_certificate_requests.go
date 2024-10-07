package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

type CreateCertificateRequestParams struct {
	CSR string `json:"csr"`
}

type CreateCertificateParams struct {
	Certificate string `json:"certificate"`
}

type GetCertificateRequestResponse struct {
	ID          int    `json:"id"`
	CSR         string `json:"csr"`
	Certificate string `json:"certificate"`
}

type CreateCertificateRequestResponse struct {
	ID int `json:"id"`
}

type DeleteCertificateRequestResponse struct {
	ID int `json:"id"`
}

type RejectCertificateRequestResponse struct {
	ID int `json:"id"`
}

type CreateCertificateResponse struct {
	ID int `json:"id"`
}

type DeleteCertificateResponse struct {
	ID int `json:"id"`
}

type RejectCertificateResponse struct {
	ID int `json:"id"`
}

// ListCertificateRequests returns all of the Certificate Requests
func ListCertificateRequests(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certs, err := env.DB.RetrieveAllCSRs()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestsResponse := make([]GetCertificateRequestResponse, len(certs))
		for i, cert := range certs {
			certificateRequestsResponse[i] = GetCertificateRequestResponse{
				ID:          cert.ID,
				CSR:         cert.CSR,
				Certificate: cert.Certificate,
			}
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, certificateRequestsResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// CreateCertificateRequest creates a new Certificate Request, and returns the id of the created row
func CreateCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateRequestParams CreateCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateRequestParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if createCertificateRequestParams.CSR == "" {
			writeError(w, http.StatusBadRequest, "csr is empty")
			return
		}
		id, err := env.DB.CreateCSR(createCertificateRequestParams.CSR)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				writeError(w, http.StatusBadRequest, "given csr already recorded")
				return
			}
			if strings.Contains(err.Error(), "csr validation failed") {
				log.Println(err)
				writeError(w, http.StatusBadRequest, "csr validation failed")
				return
			}
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestResponse := CreateCertificateRequestResponse{
			ID: int(id),
		}
		w.WriteHeader(http.StatusCreated)
		err = writeJSON(w, certificateRequestResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// GetCertificateRequest receives an id as a path parameter, and
// returns the corresponding Certificate Request
func GetCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		cert, err := env.DB.RetrieveCSR(id)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestResponse := GetCertificateRequestResponse{
			ID:          cert.ID,
			CSR:         cert.CSR,
			Certificate: cert.Certificate,
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, certificateRequestResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
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
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestResponse := DeleteCertificateRequestResponse{
			ID: int(insertId),
		}
		w.WriteHeader(http.StatusAccepted)
		err = writeJSON(w, certificateRequestResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// CreateCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func CreateCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateParams CreateCertificateParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if createCertificateParams.Certificate == "" {
			writeError(w, http.StatusBadRequest, "certificate is empty")
			return
		}
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, createCertificateParams.Certificate)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) ||
				err.Error() == "certificate does not match CSR" ||
				strings.Contains(err.Error(), "cert validation failed") {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		certificateResponse := CreateCertificateResponse{
			ID: int(insertId),
		}
		w.WriteHeader(http.StatusCreated)
		err = writeJSON(w, certificateResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

func RejectCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		insertId, err := env.DB.UpdateCSR(id, "rejected")
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		certificateResponse := RejectCertificateResponse{
			ID: int(insertId),
		}
		w.WriteHeader(http.StatusAccepted)
		err = writeJSON(w, certificateResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
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
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		insertIdStr := strconv.FormatInt(insertId, 10)
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", insertIdStr)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		certificateResponse := DeleteCertificateResponse{
			ID: int(insertId),
		}
		w.WriteHeader(http.StatusOK)
		err = writeJSON(w, certificateResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
