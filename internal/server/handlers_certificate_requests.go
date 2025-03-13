package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
)

type CreateCertificateRequestParams struct {
	CSR string `json:"csr"`
}

func (params *CreateCertificateRequestParams) IsValid() (bool, error) {
	if strings.TrimSpace(params.CSR) == "" {
		return false, errors.New("csr is required")
	}
	block, _ := pem.Decode([]byte(params.CSR))
	if block == nil {
		return false, errors.New("could not decode PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return false, fmt.Errorf("expected PEM block type 'CERTIFICATE REQUEST'")
	}
	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("could not parse CSR")
	}

	return true, nil
}

type CreateCertificateParams struct {
	CertificateChain string `json:"certificate"`
}

func (params *CreateCertificateParams) IsValid() (bool, error) {
	if strings.TrimSpace(params.CertificateChain) == "" {
		return false, errors.New("certificate is required")
	}
	block, _ := pem.Decode([]byte(params.CertificateChain))
	if block == nil {
		return false, errors.New("could not decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return false, fmt.Errorf("expected PEM block type 'CERTIFICATE'")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("could not parse certificate")
	}
	return true, nil
}

type CertificateRequest struct {
	ID               int64  `json:"id"`
	CSR              string `json:"csr"`
	CertificateChain string `json:"certificate_chain"`
	Status           string `json:"status"`
}

// ListCertificateRequests returns all of the Certificate Requests
func ListCertificateRequests(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrs, err := env.DB.ListCertificateRequestWithCertificatesWithoutCAS()
		if err != nil {
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
		valid, err := createCertificateRequestParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		newCSRID, err := env.DB.CreateCertificateRequest(createCertificateRequestParams.CSR)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "given csr already recorded")
				return
			}
			if errors.Is(err, db.ErrInvalidCertificateRequest) {
				writeError(w, http.StatusBadRequest, "csr validation failed")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		successResponse := CreateSuccessResponse{Message: "success", ID: newCSRID}
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
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		csr, err := env.DB.GetCertificateRequestAndChain(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(csr.CSR_ID))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
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
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
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

// PostCertificateRequestCertificate handler receives an id as a path parameter,
// and attempts to add a given certificate to the corresponding certificate request
func PostCertificateRequestCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateParams CreateCertificateParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		valid, err := createCertificateParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		newCertID, err := env.DB.AddCertificateChainToCertificateRequest(db.ByCSRID(idNum), createCertificateParams.CertificateChain)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) ||
				errors.Is(err, db.ErrInvalidCertificate) {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				log.Printf("pebble notify failed: %s. continuing silently.", err.Error())
			}
		}
		successResponse := CreateSuccessResponse{Message: "success", ID: newCertID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}

// RejectCertificateRequest handler receives an id as a path parameter,
// rejects the corresponding Certificate Request, and returns a http.StatusNoContent on success
func RejectCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.RejectCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
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
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "Bad Request")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
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

// RevokeCertificate handler receives an id as a path parameter,
// and attempts to revoke the corresponding certificate request
// It returns a 200 OK on success
func RevokeCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.RevokeCertificate(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
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

// SignCertificateRequest handler receives the ID of an existing active certificate authority in Notary
// to sign any certificate request available in Notary.
// It returns a 202 Accepted on success.
func SignCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		var signCertificateRequestParams SignCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&signCertificateRequestParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		caIDInt, err := strconv.ParseInt(signCertificateRequestParams.CertificateAuthorityID, 10, 64)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = env.DB.SignCertificateRequest(db.ByCSRID(idNum), db.ByCertificateAuthorityID(caIDInt))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
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
