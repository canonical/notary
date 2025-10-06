package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
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
	Email            string `json:"email"`
}

// ListCertificateRequests returns all of the Certificate Requests
func ListCertificateRequests(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}

		var csrs []db.CertificateRequestWithChain
		var err error

		filter := &db.CSRFilter{}
		if claims.RoleID == RoleCertificateRequestor {
			filter.UserID = &claims.ID
		}

		csrs, err = env.DB.ListCertificateRequestWithCertificatesWithoutCAS(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		certificateRequestsResponse := make([]CertificateRequest, len(csrs))
		for i, csr := range csrs {
			var email string
			user, err := env.DB.GetUser(db.ByUserID(csr.UserID))
			if err != nil {
				if errors.Is(err, db.ErrNotFound) {
					env.SystemLogger.Warn("user not found for certificate request", zap.Int64("user_id", csr.UserID))
					email = "unknown"
				} else {
					writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
					return
				}
			} else {
				email = user.Email
			}
			certificateRequestsResponse[i] = CertificateRequest{
				ID:               csr.CSR_ID,
				CSR:              csr.CSR,
				Status:           csr.Status,
				CertificateChain: csr.CertificateChain,
				Email:            email,
			}
		}
		err = writeResponse(w, certificateRequestsResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// CreateCertificateRequest creates a new Certificate Request, and returns the id of the created row
func CreateCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateRequestParams CreateCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateRequestParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := createCertificateRequestParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}

		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}

		newCSRID, err := env.DB.CreateCertificateRequest(createCertificateRequestParams.CSR, claims.ID)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeError(w, http.StatusBadRequest, "given csr already recorded", err, env.SystemLogger)
				return
			}
			if errors.Is(err, db.ErrInvalidCertificateRequest) {
				writeError(w, http.StatusBadRequest, "csr validation failed", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		env.AuditLogger.CertificateRequested(strconv.FormatInt(newCSRID, 10), 0,
			WithActor(claims.Email),
			WithRequest(r),
		)
		
		successResponse := CreateSuccessResponse{Message: "success", ID: newCSRID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// GetCertificateRequest receives an id as a path parameter, and
// returns the corresponding Certificate Request
func GetCertificateRequest(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}

		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}

		csr, err := env.DB.GetCertificateRequestAndChain(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		// Restrict access to certificate requestors' own requests
		if claims.RoleID == RoleCertificateRequestor && claims.ID != csr.UserID {
			writeError(w, http.StatusForbidden, "Access denied", fmt.Errorf("user does not have permission to access this certificate request"), env.SystemLogger)
			return
		}

		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(csr.CSR_ID))
		if rowFound(err) {
			writeError(w, http.StatusNotFound, "Not Found", fmt.Errorf("not found"), env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		var email string
		user, err := env.DB.GetUser(db.ByUserID(csr.UserID))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.SystemLogger.Warn("user not found for certificate request", zap.Int64("user_id", csr.UserID))
				email = "unknown"
			} else {
				writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
				return
			}
		} else {
			email = user.Email
		}

		certificateRequestResponse := CertificateRequest{
			ID:               csr.CSR_ID,
			CSR:              csr.CSR,
			CertificateChain: csr.CertificateChain,
			Status:           csr.Status,
			Email:            email,
		}

		err = writeResponse(w, certificateRequestResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}
		
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeError(w, http.StatusNotFound, "Not Found", fmt.Errorf("not found"), env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		env.AuditLogger.CertificateRequestDeleted(id,
			WithActor(claims.Email),
			WithRequest(r),
		)
		
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := createCertificateParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error(), err, env.SystemLogger)
			return
		}
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}
		
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		newCertID, err := env.DB.AddCertificateChainToCertificateRequest(db.ByCSRID(idNum), createCertificateParams.CertificateChain)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) ||
				errors.Is(err, db.ErrInvalidCertificate) {
				writeError(w, http.StatusBadRequest, "Bad Request", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		env.AuditLogger.CertificateIssued(id, 0,
			WithActor(claims.Email),
			WithRequest(r),
		)
		
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		successResponse := CreateSuccessResponse{Message: "success", ID: newCertID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}
		
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			err = fmt.Errorf("certificate request %d not found", idNum)
			writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.RejectCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		env.AuditLogger.CertificateRejected(id, 0,
			WithActor(claims.Email),
			WithRequest(r),
			WithReason("rejected by administrator"),
		)
		
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "Bad Request", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// RevokeCertificate handler receives an id as a path parameter,
// and attempts to revoke the corresponding certificate request by adding the certificate to the CRL
// It returns a 200 OK on success
func RevokeCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		
		claims, headerErr := getClaimsFromAuthorizationHeader(r.Header.Get("Authorization"), env.JWTSecret)
		if headerErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", headerErr, env.SystemLogger)
			return
		}
		
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.RevokeCertificate(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		
		env.AuditLogger.CertificateRevoked(id,
			WithActor(claims.Email),
			WithRequest(r),
		)
		
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
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
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		var signCertificateRequestParams SignCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&signCertificateRequestParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		_, err = env.DB.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			err = fmt.Errorf("certificate authority %d not found", idNum)
			writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
			return
		}
		if realError(err) {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		caIDInt, err := strconv.ParseInt(signCertificateRequestParams.CertificateAuthorityID, 10, 64)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.SignCertificateRequest(db.ByCSRID(idNum), db.ByCertificateAuthorityDenormalizedID(caIDInt), env.ExternalHostname)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		if env.SendPebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusAccepted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

func realError(err error) bool {
	return err != nil && !errors.Is(err, db.ErrNotFound)
}

func rowFound(err error) bool {
	return err == nil
}
