package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

const nextUpdateYears = 1

// extractCommonName extracts the CN from a certificate PEM string, returns "unknown" if it fails
func extractCommonName(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "unknown"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "unknown"
	}
	return cert.Subject.CommonName
}

type CertificateAuthority struct {
	ID             int64  `json:"id"`
	Enabled        bool   `json:"enabled"`
	PrivateKeyPEM  string `json:"private_key,omitempty"`
	CertificatePEM string `json:"certificate"`
	CSRPEM         string `json:"csr"`
	CRL            string `json:"crl"`
}

type CRL struct {
	CRL string `json:"crl"`
}

type CreateCertificateAuthorityParams struct {
	SelfSigned bool `json:"self_signed"`

	CommonName          string `json:"common_name"`
	SANsDNS             string `json:"sans_dns"`
	CountryName         string `json:"country_name"`
	StateOrProvinceName string `json:"state_or_province_name"`
	LocalityName        string `json:"locality_name"`
	OrganizationName    string `json:"organization_name"`
	OrganizationalUnit  string `json:"organizational_unit_name"`
	NotValidAfter       string `json:"not_valid_after"`
}

type UpdateCertificateAuthorityParams struct {
	Enabled bool `json:"enabled,omitempty"`
}

type UploadCertificateToCertificateAuthorityParams struct {
	CertificateChain string `json:"certificate_chain"`
}

type SignCertificateRequestParams struct {
	CertificateAuthorityID string `json:"certificate_authority_id"`
}

type SignCertificateAuthorityParams struct {
	CertificateAuthorityID string `json:"certificate_authority_id"`
}

func (params *CreateCertificateAuthorityParams) IsValid() (bool, error) {
	// If a country is provided, it must be exactly two letters (ISO 3166-1 alpha-2).
	if params.CountryName != "" && len(params.CountryName) != 2 {
		return false, fmt.Errorf("country_name must be a 2-letter ISO code")
	}

	// If not_valid_after is provided, it must be a valid RFC3339 timestamp and in the future.
	if params.NotValidAfter != "" {
		notValidAfter, err := time.Parse(time.RFC3339, params.NotValidAfter)
		if err != nil {
			return false, fmt.Errorf("not_valid_after must be a valid RFC3339 timestamp")
		}
		if !notValidAfter.After(time.Now()) {
			return false, errors.New("not_valid_after must be a future time")
		}
	}
	return true, nil
}

func (params *UploadCertificateToCertificateAuthorityParams) IsValid() (bool, error) {
	if strings.TrimSpace(params.CertificateChain) == "" {
		return false, errors.New("certificate_chain is required")
	}

	rest := []byte(params.CertificateChain)
	var found bool
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return false, fmt.Errorf("unexpected PEM block type: expected CERTIFICATE")
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse certificate: %v", err)
		}
		found = true
	}

	if !found {
		return false, errors.New("no valid certificate found in certificate_chain")
	}

	return true, nil
}

// createCertificateAuthority uses the input fields from the CA certificate generation form to create
// an x.509 certificate request, a private key, a CRL, and optionally a self-signed certificate. It returns them as PEM strings.
func createCertificateAuthority(fields CreateCertificateAuthorityParams) (string, string, string, string, error) {
	// Create the private key for the CA
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	skiHash := generateSKI(priv)
	// Create the certificate request for the CA
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         fields.CommonName,
			Country:            []string{fields.CountryName},
			Province:           []string{fields.StateOrProvinceName},
			Locality:           []string{fields.LocalityName},
			Organization:       []string{fields.OrganizationName},
			OrganizationalUnit: []string{fields.OrganizationalUnit},
		},
		DNSNames: []string{fields.SANsDNS},
	}
	if fields.SANsDNS != "" {
		csrTemplate.DNSNames = []string{fields.SANsDNS}
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	// If this is not a self-signed CA, don't create a self-signed certificate
	if !fields.SelfSigned {
		return csrPEM.String(), privPEM.String(), "", "", nil
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         fields.CommonName,
			Country:            []string{fields.CountryName},
			Province:           []string{fields.StateOrProvinceName},
			Locality:           []string{fields.LocalityName},
			Organization:       []string{fields.OrganizationName},
			OrganizationalUnit: []string{fields.OrganizationalUnit},
		},
		SubjectKeyId:          skiHash,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if fields.NotValidAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, fields.NotValidAfter)
		if err != nil {
			return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
		}
		template.NotAfter = notAfter
	} else {
		template.NotAfter = time.Now().AddDate(10, 0, 0) // Default 10 years
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(time.Now().UnixNano()),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().AddDate(nextUpdateYears, 0, 0),
	}, template, priv)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	crlPEM := new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err != nil {
		return "", "", "", "", fmt.Errorf("error creating certificate authority: %w", err)
	}
	return csrPEM.String(), privPEM.String(), crlPEM.String(), certPEM.String(), nil
}

// ListCertificateAuthorities handler returns a list of all Certificate Authorities
// It returns a 200 OK on success
// ListCertificateAuthorities godoc
//
//	@Summary		List certificate authorities
//	@Description	Returns all certificate authorities.
//	@Tags			certificate_authorities
//	@Produce		json
//	@Success		200	{object}	map[string][]CertificateAuthority
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities [get]
func ListCertificateAuthorities(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cas, err := env.Database.ListDenormalizedCertificateAuthorities()
		if err != nil {
			env.SystemLogger.Error("failed to list certificate authorities", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		caResponse := make([]CertificateAuthority, len(cas))
		for i, ca := range cas {
			caResponse[i] = CertificateAuthority{
				ID:             ca.CertificateAuthorityID,
				Enabled:        ca.Enabled,
				PrivateKeyPEM:  "",
				CSRPEM:         ca.CSRPEM,
				CertificatePEM: ca.CertificateChain,
				CRL:            ca.CRL,
			}
		}
		writeResponse(w, http.StatusOK, "", caResponse, env.SystemLogger)
	}
}

// CreateCertificateAuthority godoc
//
//	@Summary		Create certificate authority
//	@Description	Creates a new certificate authority.
//	@Tags			certificate_authorities
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateCertificateAuthorityParams	true	"Create certificate authority payload"
//	@Success		201		{object}	map[string]CreateSuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities [post]
func CreateCertificateAuthority(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params CreateCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			env.SystemLogger.Info("invalid certificate authority create request JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := params.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err), nil, env.SystemLogger)
			return
		}
		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}
		csrPEM, privPEM, crlPEM, certPEM, err := createCertificateAuthority(params)
		if err != nil {
			env.SystemLogger.Error("failed to create certificate authority material", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		var newCAID int64
		if certPEM != "" {
			newCAID, err = env.Database.CreateCertificateAuthority(strings.TrimSpace(csrPEM), strings.TrimSpace(privPEM), strings.TrimSpace(crlPEM), strings.TrimSpace(certPEM+certPEM), claims.ID)
		} else {
			newCAID, err = env.Database.CreateCertificateAuthority(strings.TrimSpace(csrPEM), strings.TrimSpace(privPEM), "", "", claims.ID)
		}
		if err != nil {
			env.SystemLogger.Error("failed to persist certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CACreated(int(newCAID), params.CommonName,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusCreated, "", map[string]int64{"id": newCAID}, env.SystemLogger)
	}
}

// GetCertificateAuthority godoc
//
//	@Summary		Get certificate authority
//	@Description	Returns the certificate authority for the provided ID.
//	@Tags			certificate_authorities
//	@Produce		json
//	@Param			id	path		int	true	"Certificate authority ID"
//	@Success		200	{object}	map[string]CertificateAuthority
//	@Failure		400	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id} [get]
func GetCertificateAuthority(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		ca, err := env.Database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		caResponse := CertificateAuthority{
			ID:             ca.CertificateAuthorityID,
			Enabled:        ca.Enabled,
			PrivateKeyPEM:  "",
			CSRPEM:         ca.CSRPEM,
			CertificatePEM: ca.CertificateChain,
			CRL:            ca.CRL,
		}

		writeResponse(w, http.StatusOK, "", caResponse, env.SystemLogger)
	}
}

// UpdateCertificateAuthority godoc
//
//	@Summary		Update certificate authority
//	@Description	Updates the enabled status of the certificate authority for the provided ID.
//	@Tags			certificate_authorities
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int								true	"Certificate authority ID"
//	@Param			request	body		UpdateCertificateAuthorityParams	true	"Update certificate authority payload"
//	@Success		200		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id} [put]
func UpdateCertificateAuthority(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		var params UpdateCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			env.SystemLogger.Info("invalid certificate authority update request JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		err = env.Database.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(idNum), params.Enabled)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to update certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CAUpdated(id, params.Enabled,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusOK, "", nil, env.SystemLogger)
	}
}

// DeleteCertificateAuthority godoc
//
//	@Summary		Delete certificate authority
//	@Description	Deletes the certificate authority for the provided ID.
//	@Tags			certificate_authorities
//	@Produce		json
//	@Param			id	path		int	true	"Certificate authority ID"
//	@Success		200	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id} [delete]
func DeleteCertificateAuthority(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		ca, err := env.Database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to delete certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		err = env.Database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get certificate authority before deletion", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CADeleted(int(idNum), extractCommonName(ca.CertificateChain),
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusOK, "", nil, env.SystemLogger)
	}
}

// PostCertificateAuthorityCertificate godoc
//
//	@Summary		Upload certificate authority certificate
//	@Description	Uploads a certificate chain to the certificate authority for the provided ID.
//	@Tags			certificate_authorities
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int												true	"Certificate authority ID"
//	@Param			request	body		UploadCertificateToCertificateAuthorityParams	true	"Upload certificate chain payload"
//	@Success		201		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id}/certificate [post]
func PostCertificateAuthorityCertificate(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		var UploadCertificateToCertificateAuthorityParams UploadCertificateToCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&UploadCertificateToCertificateAuthorityParams); err != nil {
			env.SystemLogger.Info("invalid certificate authority certificate upload JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}
		valid, err := UploadCertificateToCertificateAuthorityParams.IsValid()
		if !valid {
			writeResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err), nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		err = env.Database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(idNum), UploadCertificateToCertificateAuthorityParams.CertificateChain)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to upload certificate authority certificate", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CACertificateUploaded(id,
			log.WithActor(claims.Email),
			log.WithRequest(r),
		)

		writeResponse(w, http.StatusCreated, "", nil, env.SystemLogger)
	}
}

// SignCertificateAuthority godoc
//
//	@Summary		Sign certificate authority
//	@Description	Uses the provided signing certificate authority to sign the pending intermediate certificate authority for the provided ID.
//	@Tags			certificate_authorities
//	@Accept			json
//	@Produce		json
//	@Param			id		path		int							true	"Certificate authority ID"
//	@Param			request	body		SignCertificateAuthorityParams	true	"Sign certificate authority payload"
//	@Success		202		{object}	map[string]SuccessResponse
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		404		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id}/sign [post]
func SignCertificateAuthority(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			env.SystemLogger.Error("failed to get certificate authority to be signed", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		var signCertificateAuthorityParams SignCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&signCertificateAuthorityParams); err != nil {
			env.SystemLogger.Info("invalid certificate authority sign request JSON", zap.Error(err))
			writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		caIDInt, err := strconv.ParseInt(signCertificateAuthorityParams.CertificateAuthorityID, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}
		caToBeSigned, err := env.Database.GetCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid certificate authority ID", nil, env.SystemLogger)
			return
		}
		err = env.Database.SignCertificateRequest(db.ByCSRID(caToBeSigned.CSRID), db.ByCertificateAuthorityDenormalizedID(caIDInt), env.ExternalHostname)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to sign certificate authority", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CertificateSigned(id, signCertificateAuthorityParams.CertificateAuthorityID,
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

// GetCertificateAuthorityCRL godoc
//
//	@Summary		Get certificate authority CRL
//	@Description	Returns the certificate revocation list for the certificate authority with the provided ID.
//	@Tags			certificate_authorities
//	@Produce		json
//	@Param			id	path		int	true	"Certificate authority ID"
//	@Success		200	{object}	map[string]CRL
//	@Failure		400	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Router			/api/v1/certificate_authorities/{id}/crl [get]
func GetCertificateAuthorityCRL(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		ca, err := env.Database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			env.SystemLogger.Error("failed to get certificate authority CRL", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		crlResponse := CRL{CRL: ca.CRL}

		writeResponse(w, http.StatusOK, "", crlResponse, env.SystemLogger)
	}
}

// RevokeCertificateAuthorityCertificate godoc
//
//	@Summary		Revoke certificate authority certificate
//	@Description	Revokes the certificate authority certificate for the provided ID by adding its serial number to the CRL.
//	@Tags			certificate_authorities
//	@Produce		json
//	@Param			id	path		int	true	"Certificate authority ID"
//	@Success		202	{object}	map[string]SuccessResponse
//	@Failure		400	{object}	map[string]string
//	@Failure		401	{object}	map[string]string
//	@Failure		404	{object}	map[string]string
//	@Failure		500	{object}	map[string]string
//	@Security		cookieAuth
//	@Router			/api/v1/certificate_authorities/{id}/revoke [post]
func RevokeCertificateAuthorityCertificate(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeResponse(w, http.StatusBadRequest, "invalid ID", nil, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
		if cookieErr != nil {
			env.SystemLogger.Info("failed to get JWT claims from cookie", zap.Error(cookieErr))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		ca, err := env.Database.GetCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			env.SystemLogger.Info("could not get certificate authority", zap.Error(err))
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		err = env.Database.RevokeCertificate(db.ByCSRID(ca.CSRID))
		if err != nil {
			env.SystemLogger.Warn("could not revoke certificate", zap.Error(err))
			if errors.Is(err, db.ErrNotFound) {
				writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
				return
			}
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		env.AuditLogger.CACertificateRevoked(id,
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
