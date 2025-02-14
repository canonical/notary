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
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/sqlair"
)

type CertificateAuthority struct {
	CertificateAuthorityID int64       `json:"certificate_authority_id"`
	Status                 db.CAStatus `json:"status"`
	PrivateKeyPEM          string      `json:"private_key,omitempty"`
	CertificatePEM         string      `json:"certificate"`
	CSRPEM                 string      `json:"csr"`
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
	Status string `json:"status,omitempty"`
}

type UploadCertificateToCertificateAuthorityParams struct {
	CertificateChain string `json:"certificate_chain"`
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

func (updateCAParams *UpdateCertificateAuthorityParams) IsValid() (bool, error) {
	if updateCAParams.Status == "" {
		return false, errors.New("status is required")
	}
	if _, err := db.NewStatusFromString(updateCAParams.Status); err != nil {
		return false, err
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
// an x.509 certificate request, a private key, and optionally a self-signed certificate. It returns them as PEM strings.
func createCertificateAuthority(fields CreateCertificateAuthorityParams) (string, string, string) {
	// Create the private key for the CA
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", ""
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return "", "", ""
	}

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
		return "", "", ""
	}

	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	if err != nil {
		return "", "", ""
	}

	// If this is not a self-signed CA, don't create a self-signed certificate
	if !fields.SelfSigned {
		return csrPEM.String(), privPEM.String(), ""
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
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if fields.NotValidAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, fields.NotValidAfter)
		if err != nil {
			return "", "", ""
		}
		template.NotAfter = notAfter
	} else {
		template.NotAfter = time.Now().AddDate(10, 0, 0) // Default 10 years
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", ""
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		return "", "", ""
	}

	return csrPEM.String(), privPEM.String(), certPEM.String()
}

// ListCertificateAuthorities handler returns a list of all Certificate Authorities
// It returns a 200 OK on success
func ListCertificateAuthorities(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cas, err := env.DB.ListDenormalizedCertificateAuthorities()
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		caResponse := make([]CertificateAuthority, len(cas))
		for i, ca := range cas {
			caResponse[i] = CertificateAuthority{
				CertificateAuthorityID: ca.CertificateAuthorityID,
				Status:                 ca.Status,
				PrivateKeyPEM:          "",
				CSRPEM:                 ca.CSRPEM,
				CertificatePEM:         ca.CertificatePEM,
			}
		}
		err = writeResponse(w, caResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
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
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		valid, err := params.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		csrPEM, privPEM, certPEM := createCertificateAuthority(params)
		if csrPEM == "" || privPEM == "" {
			writeError(w, http.StatusInternalServerError, "Failed to create certificate authority")
			return
		}
		if certPEM != "" {
			err = env.DB.CreateCertificateAuthority(csrPEM, privPEM, certPEM+certPEM)
		} else {
			err = env.DB.CreateCertificateAuthority(csrPEM, privPEM, "")
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create certificate authority")
			return
		}

		successResponse := SuccessResponse{Message: "Certificate Authority created successfully"}
		err = writeResponse(w, successResponse, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
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
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}

		ca, err := env.DB.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(idNum))
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		caResponse := CertificateAuthority{
			CertificateAuthorityID: ca.CertificateAuthorityID,
			Status:                 ca.Status,
			PrivateKeyPEM:          "",
			CSRPEM:                 ca.CSRPEM,
			CertificatePEM:         ca.CertificatePEM,
		}

		err = writeResponse(w, caResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
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
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}

		var params UpdateCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		valid, err := params.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		status, err := db.NewStatusFromString(params.Status)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}
		err = env.DB.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(idNum), status)
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
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
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
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}

		err = env.DB.DeleteCertificateAuthority(db.ByCertificateAuthorityID(idNum))
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
		err = writeResponse(w, successResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
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
			writeError(w, http.StatusBadRequest, "Invalid ID")
			return
		}
		var UploadCertificateToCertificateAuthorityParams UploadCertificateToCertificateAuthorityParams
		if err := json.NewDecoder(r.Body).Decode(&UploadCertificateToCertificateAuthorityParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		valid, err := UploadCertificateToCertificateAuthorityParams.IsValid()
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Errorf("Invalid request: %s", err).Error())
			return
		}

		err = env.DB.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(idNum), UploadCertificateToCertificateAuthorityParams.CertificateChain)
		if err != nil {
			log.Println(err)
			if errors.Is(err, sqlair.ErrNoRows) {
				writeError(w, http.StatusNotFound, "Not Found")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		err = writeResponse(w, SuccessResponse{Message: "success"}, http.StatusCreated)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
}
