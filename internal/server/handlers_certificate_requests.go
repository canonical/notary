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

	"github.com/canonical/notary/internal/backends/observability/log"
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
// ListCertificateRequests godoc
//
//	@Summary		List certificate requests
//	@Description	Returns certificate requests visible to the authenticated user.
//	@Tags			certificate_requests
//	@Produce		json
//	@Success		200	{object}	map[string][]CertificateRequest
//	@Failure		401	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests [get]
func ListCertificateRequests(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		var csrs []db.CertificateRequestWithChain
		var err error

		filter := &db.CSRFilter{}
		if RoleID(claims.RoleID) == RoleCertificateRequestor {
			filter.UserEmail = &claims.Email
		}

		csrs, err = env.Database.ListCertificateRequestWithCertificatesWithoutCAS(filter)
		if err != nil {
			env.SystemLogger.Error("failed to list certificate requests", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		certificateRequestsResponse := make([]CertificateRequest, len(csrs))
		for i, csr := range csrs {
			var email string
			user, err := env.Database.GetUser(db.ByEmail(csr.UserEmail))
			if err != nil {
				if errors.Is(err, db.ErrNotFound) {
					env.SystemLogger.Warn("user not found for certificate request", zap.String("user_email", csr.UserEmail))
					// Here, we're purposefully hiding the email of an account that's deleted even though we have the information
					email = "unknown"
				} else {
					env.SystemLogger.Error("failed to get user for certificate request", zap.Error(err), zap.String("user_email", csr.UserEmail))
					writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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
		writeResponse(w, http.StatusOK, "", certificateRequestsResponse, env.SystemLogger)
	}
}

// CreateCertificateRequest godoc
//
//	@Summary		Create certificate request
//	@Description	Creates a new certificate signing request for the authenticated user.
//	@Tags			certificate_requests
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateCertificateRequestParams	true	"Certificate request payload"
//	@Success		201		{object}	map[string]CreateSuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests [post]
func CreateCertificateRequest(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateRequestParams CreateCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateRequestParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := createCertificateRequestParams.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err), nil, env.SystemLogger)
			return
		}
		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		newCSRID, err := env.Database.CreateCertificateRequest(createCertificateRequestParams.CSR, claims.Email)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyExists) {
				writeResponse(w, http.StatusBadRequest, "given csr already recorded", nil, env.SystemLogger)
				return
			}
			if errors.Is(err, db.ErrInvalidCertificateRequest) {
				writeResponse(w, http.StatusBadRequest, "csr validation failed", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to create certificate request", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateRequested(strconv.FormatInt(newCSRID, 10), 0,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusCreated, "", map[string]int64{"id": newCSRID}, env.SystemLogger)
	}
}

// GetCertificateRequest godoc
//
//	@Summary		Get certificate request
//	@Description	Returns the certificate request for the provided request ID.
//	@Tags			certificate_requests
//	@Produce		json
//	@Param			id	path		int	true	"Certificate request ID"
//	@Success		200	{object}	map[string]CertificateRequest
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		403	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id} [get]
func GetCertificateRequest(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, headerErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if headerErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(headerErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		csr, err := env.Database.GetCertificateRequestAndChain(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get certificate request", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		// Restrict access to certificate requestors' own requests
		if RoleID(claims.RoleID) == RoleCertificateRequestor && claims.Email != csr.UserEmail {
			env.SystemLogger.Warn("certificate request access denied", zap.String("requester_email", claims.Email), zap.String("owner_email", csr.UserEmail), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusForbidden, "access denied", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(csr.CSR_ID))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", csr.CSR_ID))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		var email string
		user, err := env.Database.GetUser(db.ByEmail(csr.UserEmail))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				env.SystemLogger.Warn("user not found for certificate request", zap.String("user_email", csr.UserEmail))
				// Here, we're purposefully hiding the email of an account that's deleted even though we have the information
				email = "unknown"
			} else {
				env.SystemLogger.Error("failed to get user for certificate request", zap.Error(err), zap.String("user_email", csr.UserEmail))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
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

		writeResponse(w, http.StatusOK, "", certificateRequestResponse, env.SystemLogger)
	}
}

// DeleteCertificateRequest godoc
//
//	@Summary		Delete certificate request
//	@Description	Deletes the certificate request for the provided request ID.
//	@Tags			certificate_requests
//	@Produce		json
//	@Param			id	path		int	true	"Certificate request ID"
//	@Success		202	{object}	map[string]SuccessResponse
//	@Failure		404	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id} [delete]
func DeleteCertificateRequest(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		err = env.Database.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete certificate request", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateRequestDeleted(id,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

// PostCertificateRequestCertificate godoc
//
//	@Summary		Upload certificate for certificate request
//	@Description	Uploads a certificate chain for the provided certificate request ID.
//	@Tags			certificate_requests
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int						true	"Certificate request ID"
//	@Param			request	body		CreateCertificateParams	true	"Certificate upload payload"
//	@Success		201		{object}	map[string]CreateSuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id}/certificate [post]
func PostCertificateRequestCertificate(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createCertificateParams CreateCertificateParams
		if err := json.NewDecoder(r.Body).Decode(&createCertificateParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := createCertificateParams.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err), nil, env.SystemLogger)
			return
		}
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		newCertID, err := env.Database.AddCertificateChainToCertificateRequest(db.ByCSRID(idNum), createCertificateParams.CertificateChain)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) ||
				errors.Is(err, db.ErrInvalidCertificate) {
				writeResponse(w, http.StatusBadRequest, "bad request", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to add certificate chain to certificate request", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateIssued(id, 0,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		writeResponse(w, http.StatusCreated, "", map[string]int64{"id": newCertID}, env.SystemLogger)
	}
}

// RejectCertificateRequest godoc
//
//	@Summary		Reject certificate request
//	@Description	Rejects the certificate request for the provided request ID.
//	@Tags			certificate_requests
//	@Produce		json
//	@Param			id	path		int	true	"Certificate request ID"
//	@Success		202	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id}/reject [post]
func RejectCertificateRequest(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		err = env.Database.RejectCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to reject certificate request", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateRejected(id, 0,
			log.WithActor(claims.Email),
			log.WithRequest(r),
			log.WithReason("rejected by administrator"),
		)

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

// DeleteCertificate godoc
//
//	@Summary		Delete certificate
//	@Description	Deletes the certificate associated with the provided certificate request ID.
//	@Tags			certificate_requests
//	@Produce		json
//	@Param			id	path		int	true	"Certificate request ID"
//	@Success		200	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id}/certificate [delete]
func DeleteCertificate(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		err = env.Database.DeleteCertificateRequest(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusBadRequest, "bad request", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete certificate", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateDeleted(id,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		writeResponse(w, http.StatusOK, "", nil, env.SystemLogger)
	}
}

// RevokeCertificate godoc
//
//	@Summary		Revoke certificate
//	@Description	Revokes the certificate associated with the provided certificate request ID.
//	@Tags			certificate_requests
//	@Produce		json
//	@Param			id	path		int	true	"Certificate request ID"
//	@Success		202	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id}/certificate/revoke [post]
func RevokeCertificate(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		err = env.Database.RevokeCertificate(db.ByCSRID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to revoke certificate", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateRevoked(id,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

// SignCertificateRequest godoc
//
//	@Summary		Sign certificate request
//	@Description	Signs the certificate request using the provided certificate authority ID.
//	@Tags			certificate_requests
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int							true	"Certificate request ID"
//	@Param			request	body		SignCertificateRequestParams	true	"Certificate signing payload"
//	@Success		202		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_requests/{id}/sign [post]
func SignCertificateRequest(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		var signCertificateRequestParams SignCertificateRequestParams
		if err := json.NewDecoder(r.Body).Decode(&signCertificateRequestParams); err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Warn("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		_, err = env.Database.GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))
		if rowFound(err) {
			writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
			return
		}
		if realError(err) {
			env.SystemLogger.Error("failed to check whether certificate request belongs to a certificate authority", zap.Error(err), zap.Int64("csr_id", idNum))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		caIDInt, err := strconv.ParseInt(signCertificateRequestParams.CertificateAuthorityID, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid certificate authority ID", nil, env.SystemLogger)
			return
		}
		err = env.Database.SignCertificateRequest(db.ByCSRID(idNum), db.ByCertificateAuthorityDenormalizedID(caIDInt), env.ExternalHostname)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to sign certificate request", zap.Error(err), zap.Int64("csr_id", idNum), zap.Int64("certificate_authority_id", caIDInt))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateSigned(id, signCertificateRequestParams.CertificateAuthorityID,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		if env.ShouldEnablePebbleNotifications {
			err := SendPebbleNotification(CertificateUpdate, idNum)
			if err != nil {
				env.SystemLogger.Warn("pebble notify failed", zap.Error(err))
			}
		}
		writeResponse(w, http.StatusAccepted, "", nil, env.SystemLogger)
	}
}

func realError(err error) bool {
	return err != nil && !errors.Is(err, db.ErrNotFound)
}

func rowFound(err error) bool {
	return err == nil
}
