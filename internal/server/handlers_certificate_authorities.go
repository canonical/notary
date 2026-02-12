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

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
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
func ListCertificateAuthorities(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cas, err := env.DB.ListDenormalizedCertificateAuthorities()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
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
		err = writeResponse(w, caResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// CreateCertificateAuthority handler creates a new Certificate Authority
// It returns a 201 Created on success
func CreateCertificateAuthority(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params CreateCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := params.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %s", err), err, env.SystemLogger)
			return
		}
		claims, cookieErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if cookieErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", cookieErr, env.SystemLogger)
			return
		}
		csrPEM, privPEM, crlPEM, certPEM, err := createCertificateAuthority(params)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create certificate authority", err, env.SystemLogger)
			return
		}
		var newCAID int64
		if certPEM != "" {
			newCAID, err = env.DB.CreateCertificateAuthority(strings.TrimSpace(csrPEM), strings.TrimSpace(privPEM), strings.TrimSpace(crlPEM), strings.TrimSpace(certPEM+certPEM), claims.ID)
		} else {
			newCAID, err = env.DB.CreateCertificateAuthority(strings.TrimSpace(csrPEM), strings.TrimSpace(privPEM), "", "", claims.ID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create certificate authority", err, env.SystemLogger)
			return
		}

		env.AuditLogger.CACreated(int(newCAID), params.CommonName,
			logging.WithActor(claims.Email),
			logging.WithRequest(r),
		)

		successResponse := CreateSuccessResponse{Message: "Certificate Authority created successfully", ID: newCAID}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// GetCertificateAuthority handler returns a Certificate Authority given its id
// It returns a 200 OK on success
func GetCertificateAuthority(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}

		ca, err := env.DB.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
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

		err = writeResponse(w, caResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// UpdateCertificateAuthority handler updates a Certificate Authority given its id
// It returns a 200 OK on success
func UpdateCertificateAuthority(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		var params UpdateCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if cookieErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", cookieErr, env.SystemLogger)
			return
		}

		err = env.DB.UpdateCertificateAuthorityEnabledStatus(db.ByCertificateAuthorityID(idNum), params.Enabled)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.CAUpdated(id, params.Enabled,
			logging.WithActor(claims.Email),
			logging.WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// DeleteCertificateAuthority handler deletes a Certificate Authority given its id
// It returns a 200 OK on success
func DeleteCertificateAuthority(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if cookieErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", cookieErr, env.SystemLogger)
			return
		}

		ca, err := env.DB.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		err = env.DB.DeleteCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.CADeleted(int(idNum), extractCommonName(ca.CertificateChain),
			logging.WithActor(claims.Email),
			logging.WithRequest(r),
		)

		successResponse := SuccessResponse{Message: "success"}
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// PostCertificateAuthorityCertificate handler uploads a certificate chain to a Certificate Authority given its id
// It returns a 201 Created on success
func PostCertificateAuthorityCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}
		var UploadCertificateToCertificateAuthorityParams UploadCertificateToCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&UploadCertificateToCertificateAuthorityParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		valid, err := UploadCertificateToCertificateAuthorityParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %s", err), err, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if cookieErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", cookieErr, env.SystemLogger)
			return
		}

		err = env.DB.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityDenormalizedID(idNum), UploadCertificateToCertificateAuthorityParams.CertificateChain)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.CACertificateUploaded(id,
			logging.WithActor(claims.Email),
			logging.WithRequest(r),
		)

		err = writeResponse(w, SuccessResponse{Message: "success"}, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// SignCertificateAuthority handler receives the ID of an existing enabled certificate authority in Notary
// to sign any pending intermediate certificate authority available in Notary.
// It returns a 202 Accepted on success.
func SignCertificateAuthority(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		var signCertificateAuthorityParams SignCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&signCertificateAuthorityParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		caIDInt, err := strconv.ParseInt(signCertificateAuthorityParams.CertificateAuthorityID, 10, 64)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		caToBeSigned, err := env.DB.GetCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.SignCertificateRequest(db.ByCSRID(caToBeSigned.CSRID), db.ByCertificateAuthorityDenormalizedID(caIDInt), env.ExternalHostname)
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

// GetCertificateAuthorityCRL handler returns the CRL of the associated CA
// It returns a 200 OK on success
func GetCertificateAuthorityCRL(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}

		ca, err := env.DB.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityDenormalizedID(idNum))
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		crlResponse := CRL{CRL: ca.CRL}

		err = writeResponse(w, crlResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// RevokeCertificateAuthorityCertificate handler receives an id as a path parameter,
// and revokes the corresponding certificate by placing the certificate serial number to the CRL
// It returns a 200 OK on success
func RevokeCertificateAuthorityCertificate(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		idNum, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid ID", err, env.SystemLogger)
			return
		}

		claims, cookieErr := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if cookieErr != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", cookieErr, env.SystemLogger)
			return
		}

		ca, err := env.DB.GetCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			env.SystemLogger.Info("could not get certificate authority", zap.Error(err))
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		err = env.DB.RevokeCertificate(db.ByCSRID(ca.CSRID))
		if err != nil {
			env.SystemLogger.Warn("could not revoke certificate", zap.Error(err))
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusNotFound, "Not Found", err, env.SystemLogger)
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}

		env.AuditLogger.CACertificateRevoked(id,
			logging.WithActor(claims.Email),
			logging.WithRequest(r),
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
