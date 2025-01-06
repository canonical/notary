package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/sqlair"
)

type CreateCertificateRequestParams struct {
	CSR string `json:"csr"`
}

type CreateCertificateParams struct {
	CertificateChain string `json:"certificate"`
}

type CertificateRequest struct {
	ID               int    `json:"id"`
	CSR              string `json:"csr"`
	CertificateChain string `json:"certificate_chain"`
	Status           string `json:"status"`
}

// ListCertificateRequests returns all of the Certificate Requests
func ListCertificateRequests(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrs, err := env.DB.ListCertificateRequestWithCertificates()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestsResponse := make([]CertificateRequest, len(csrs))
		for i, csr := range csrs {
			certificateRequestsResponse[i] = CertificateRequest{
				ID:               csr.CSR_ID,
				CSR:              csr.CSR,
				Status:           csr.Status,
				CertificateChain: csr.CertificateChain,
			}
		}
		err = writeResponse(w, certificateRequestsResponse, http.StatusOK)
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
			writeError(w, http.StatusBadRequest, "csr is missing")
			return
		}
		err := env.DB.CreateCertificateRequest(createCertificateRequestParams.CSR)
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
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
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
		idNum, err := strconv.Atoi(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		csr, err := env.DB.GetCertificateRequestAndChain(db.ByCSRID(idNum))
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		certificateRequestResponse := CertificateRequest{
			ID:               csr.CSR_ID,
			CSR:              csr.CSR,
			CertificateChain: csr.CertificateChain,
			Status:           csr.Status,
		}
		err = writeResponse(w, certificateRequestResponse, http.StatusOK)
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
		idNum, err := strconv.Atoi(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
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
		if createCertificateParams.CertificateChain == "" {
			writeError(w, http.StatusBadRequest, "certificate is missing")
			return
		}
		id := r.PathValue("id")
		idNum, err := strconv.Atoi(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.AddCertificateChainToCertificateRequest(db.ByCSRID(idNum), createCertificateParams.CertificateChain)
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) ||
				err.Error() == "certificate does not match CSR" ||
				strings.Contains(err.Error(), "cert validation failed") {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", id)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

func RejectCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.Atoi(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.RejectCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", id)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
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
		idNum, err := strconv.Atoi(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification("canonical.com/notary/certificate/update", id)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
