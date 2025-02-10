package server_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/canonical/notary/internal/server"
)

const (
	selfSignedCACertificatePK = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	selfSignedCACertificate = `-----BEGIN CERTIFICATE-----
MIIGHzCCBAegAwIBAgIIGCEGnc3aBTkwDQYJKoZIhvcNAQELBQAwgaIxGDAWBgNV
BAYTD1Rlc3RpbmcgQ291bnRyeTEWMBQGA1UECBMNVGVzdGluZyBTdGF0ZTEZMBcG
A1UEBxMQVGVzdGluZyBMb2NhbGl0eTEdMBsGA1UEChMUVGVzdGluZyBPcmdhbml6
YXRpb24xEzARBgNVBAsTClRlc3RpbmcgT1UxHzAdBgNVBAMTFlRlc3RpbmcgU2Vs
ZiBTaWduZWQgQ0EwHhcNMjUwMjA0MTQxMDA1WhcNMzUwMjA0MTQxMDA1WjCBojEY
MBYGA1UEBhMPVGVzdGluZyBDb3VudHJ5MRYwFAYDVQQIEw1UZXN0aW5nIFN0YXRl
MRkwFwYDVQQHExBUZXN0aW5nIExvY2FsaXR5MR0wGwYDVQQKExRUZXN0aW5nIE9y
Z2FuaXphdGlvbjETMBEGA1UECxMKVGVzdGluZyBPVTEfMB0GA1UEAxMWVGVzdGlu
ZyBTZWxmIFNpZ25lZCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AKs8LIateM9NaH/0wjvptV1vZPES4i3HtmlRCtVY7lgEd6fB+Dodek5BVIV518mP
uoFrPgyimol+SXpM9QDyhktIBjjGxlkH43Uj9eiR7wPNM4umDMVfL3PKYgnR8ytt
hfd7U7FcyQS9QKUCvk5oUtlozyjPbTmymn6OrjYB3e/HhB1Z/kAZMLw/B6QpwO9y
2m0cspSdTQvKfnx0/PrdB4zVWTbBGTs1hWSe+eaEmXVfePSrmFZ2Q3/mappruUoM
CPZZfdIQCtiJpO4RJurft1YkXRPDG5i0RQcpC4YFmWJydsMxvf55+B8piZkrfAcz
4vkT321zggb3QkXvTFQ7QsB4RrpDjN8hf7H0HuuRAQEwRNj7ESVhiKHmmi4yua0+
gr0J3O2Cl2r/BjkKAJ/qPKirr7H+lyLZUQC1n8MFpnRH2yF96npfj9oTReIlKMrc
0CiAYjFLfSAD8FuWYe41Su4ZtUr/eD+lCJKm3TIKGv8JfVPrxTouM4IxlPKNzI8l
y+9erWgv+TvKBgc7TQzZ3OAeD+Ovg1fzchqqeRPw032ab7JUaSlIzpovIPCWgyMq
ZdJtv/NuXdPqBuZz6xwkC8F21VgdlKcHzHBeibYdEmyDOwRv9TZyjeTnMyJIaDdo
pbERRTTWvmRDyOGhs2/SeR3+Hetwk81bQd/EnZ4e6zMVAgMBAAGjVzBVMA4GA1Ud
DwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSbXLqZuUAgHvDfdpdDNDggifOgETANBgkqhkiG9w0BAQsFAAOC
AgEAKlIcm2sMw6a9PoNFUXLHkGo46Lao1uRJ51tNGBXasbkznb3N8pr0vhVWQk7W
QM8nd8t8yvaQ7ELo/SapBkjTyu8SwPRVbnXjl1Wke3A34VMusjhIGPNsjgI6zq8i
rmzzFSNGb+T0AngOc6dMC9N2pAWFHnmzty7Oi39R/jhOmD38wWCMyS1Lui5tXIMJ
hk/PnVEMF3Rx4rV8FBZh3IJE5O2hB4OCTQVh3w2kOI5+YRWTJm223WfHz7XHR2Ny
E6yjQhPeglxspeNufhD1H8B49/XuIsHqOBrIPUxztyuBJwXz0KuFitbLrRHLaz2T
9Ox0i6jEB5f4RU1AiwpM6KE7bFkXmWIYeOykQq7Rj0qGdo50MABGAErIIXpcRzvn
0r3y1PCvjntdrc9IG8b0bQhVss5Irr9+5wdn90lnKAi2wASmRxbYNVuIi6BpXJvk
lFukciXd3eW7qZrgUFzS2nBwXv7wlT6e7pfGChSrE+dlh6QBHkDlHU2FdwdAc8BX
GbaLCYgW2R7/cgFG25APKkLxVzuIVYCQzIc94vyTqdhEhdQfvDTnnE/Nj//lVJBp
vpdEAlIxCc8EPphBf2okYk9nbda/3fTIBlYhXo3jGw/luYY+rv3YBMzPJ9KXkfxH
nCSo5Rj3yTrtNYFLnu+iLCvMb5PcJXE55Pu5OYGktHnvMgc=
-----END CERTIFICATE-----`
)

type CreateCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func createCertificateAuthority(url string, client *http.Client, adminToken string, ca server.CreateCertificateAuthorityParams) (int, *CreateCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(ca)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var createCertificateAuthorityResponse CreateCertificateAuthorityResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &createCertificateAuthorityResponse, nil
}

type ListCertificateAuthoritiesResponse struct {
	Result []server.CertificateAuthority `json:"result"`
	Error  string                        `json:"error,omitempty"`
}

func listCertificateAuthorities(url string, client *http.Client, adminToken string) (int, *ListCertificateAuthoritiesResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var certificateAuthoritiesResponse ListCertificateAuthoritiesResponse
	if err := json.NewDecoder(res.Body).Decode(&certificateAuthoritiesResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &certificateAuthoritiesResponse, nil
}

type GetCertificateAuthorityResponse struct {
	Result server.CertificateAuthority `json:"result"`
	Error  string                      `json:"error,omitempty"`
}

func getCertificateAuthority(url string, client *http.Client, adminToken string, id int) (int, *GetCertificateAuthorityResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var getCertificateAuthorityResponse GetCertificateAuthorityResponse
	if err := json.NewDecoder(res.Body).Decode(&getCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &getCertificateAuthorityResponse, nil
}

type UpdateCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func updateCertificateAuthority(url string, client *http.Client, adminToken string, id int, status server.UpdateCertificateAuthorityParams) (int, *UpdateCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(status)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("PUT", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var updateCertificateAuthorityResponse UpdateCertificateAuthorityResponse
	if err := json.NewDecoder(res.Body).Decode(&updateCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &updateCertificateAuthorityResponse, nil
}

func deleteCertificateAuthority(url string, client *http.Client, adminToken string, id int) (int, error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

type UploadCertificateToCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func uploadCertificateToCertificateAuthority(url string, client *http.Client, adminToken string, id int, cert server.UploadCertificateToCertificateAuthorityParams) (int, *UploadCertificateToCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id)+"/certificate", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var uploadCertificateToCertificateAuthorityResponse UploadCertificateToCertificateAuthorityResponse
	if err := json.NewDecoder(res.Body).Decode(&uploadCertificateToCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &uploadCertificateToCertificateAuthorityResponse, nil
}

// The order of the tests is important, as some tests depend on the state of the server after previous tests.
func TestSelfSignedCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	db_path := filepath.Join(tempDir, "db.sqlite3")
	ts, _, err := setupServer(db_path)
	if err != nil {
		t.Fatalf("couldn't create test server: %s", err)
	}
	defer ts.Close()
	client := ts.Client()

	var adminToken string
	var nonAdminToken string
	t.Run("prepare user accounts and tokens", prepareAccounts(ts.URL, client, &adminToken, &nonAdminToken))

	t.Run("1. List certificate authorities", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 0 {
			t.Fatalf("expected no certificate authorities, got %d", len(listCertRequestsResponse.Result))
		}
	})

	t.Run("2. Create self signed certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := server.CreateCertificateAuthorityParams{
			SelfSigned: true,

			CommonName:          "Self Signed CA",
			SANsDNS:             "example.com",
			CountryName:         "TR",
			StateOrLocalityName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := createCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCAResponse.Error != "" {
			t.Fatalf("expected success, got %s", createCAResponse.Error)
		}
	})

	t.Run("3. Get all CA's - 1 should be there and active", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 1 {
			t.Fatalf("expected 1 certificate authority, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].Status != "Active" {
			t.Fatalf("expected active status, got %s", listCertRequestsResponse.Result[0].Status)
		}
		if listCertRequestsResponse.Result[0].CertificatePEM == "" {
			t.Fatalf("expected certificate to have been created, got empty")
		}
	})

	t.Run("4. Make a new Intermediate CA", func(t *testing.T) {
		createCertificatAuthorityParams := server.CreateCertificateAuthorityParams{
			SelfSigned: false,

			CommonName:          "Not Self Signed CA",
			SANsDNS:             "examplest.com",
			CountryName:         "TR",
			StateOrLocalityName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := createCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCAResponse.Error != "" {
			t.Fatalf("expected success, got %s", createCAResponse.Error)
		}
	})
	t.Run("5. Get all CA's - 2 should be there, one active one pending", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificate authority, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].Status != "Active" {
			t.Fatalf("expected active status, got %s", listCertRequestsResponse.Result[0].Status)
		}
		if listCertRequestsResponse.Result[1].Status != "Pending" {
			t.Fatalf("expected pending status, got %s", listCertRequestsResponse.Result[1].Status)
		}
	})

	var IntermediateCACSR string
	t.Run("6. Get CA by ID", func(t *testing.T) {
		statusCode, getCAResponse, err := getCertificateAuthority(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCAResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCAResponse.Error)
		}
		if getCAResponse.Result.CertificateAuthorityID != 2 {
			t.Fatalf("expected ID %d, got %d", 2, getCAResponse.Result.CertificateAuthorityID)
		}
		if getCAResponse.Result.Status != "Pending" {
			t.Fatalf("expected pending status, got %s", getCAResponse.Result.Status)
		}
		if getCAResponse.Result.CSRPEM == "" {
			t.Fatalf("expected CSR to be set")
		}
		if getCAResponse.Result.CertificatePEM != "" {
			t.Fatalf("expected certificate to not be created yet")
		}
		IntermediateCACSR = getCAResponse.Result.CSRPEM
	})

	t.Run("6. Sign the intermediate CA's CSR", func(t *testing.T) {
		signedCert := signCSR(IntermediateCACSR)
		statusCode, uploadCertificateResponse, err := uploadCertificateToCertificateAuthority(ts.URL, client, adminToken, 2, server.UploadCertificateToCertificateAuthorityParams{CertificateChain: signedCert + selfSignedCACertificate})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if uploadCertificateResponse.Error != "" {
			t.Fatalf("expected success, got %s", uploadCertificateResponse.Error)
		}
	})
	t.Run("7. Get all CA's - 2 should be there and both active", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].Status != "Active" {
			t.Fatalf("expected first CA to be active")
		}
		if listCertRequestsResponse.Result[1].Status != "Active" {
			t.Fatalf("expected second CA to be active")
		}
	})
	t.Run("8. Make first CA legacy", func(t *testing.T) {
		statusCode, makeLegacyResponse, err := updateCertificateAuthority(ts.URL, client, adminToken, 1, server.UpdateCertificateAuthorityParams{Status: "Legacy"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if makeLegacyResponse.Error != "" {
			t.Fatalf("expected success, got %s", makeLegacyResponse.Error)
		}
	})
	t.Run("9. Get all CA's - 1 active 1 legacy should be there", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].Status != "Legacy" {
			t.Fatalf("expected first CA to be legacy")
		}
		if listCertRequestsResponse.Result[1].Status != "Active" {
			t.Fatalf("expected second CA to be active")
		}
	})
	t.Run("10. Delete first CA", func(t *testing.T) {
		statusCode, err := deleteCertificateAuthority(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
	})
	t.Run("11. Get all CA's - 1 active should be there", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCertRequestsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCertRequestsResponse.Error)
		}
		if len(listCertRequestsResponse.Result) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].Status != "Active" {
			t.Fatalf("expected first CA to be active")
		}
	})
}

// sign a csr with a self signed ca
func signCSR(csr string) string {
	csrDER, _ := pem.Decode([]byte(csr))                             //nolint: errcheck
	csrTemplate, _ := x509.ParseCertificateRequest(csrDER.Bytes)     //nolint: errcheck
	signingCertDER, _ := pem.Decode([]byte(selfSignedCACertificate)) //nolint: errcheck
	signingCert, _ := x509.ParseCertificate(signingCertDER.Bytes)    //nolint: errcheck
	pkDER, _ := pem.Decode([]byte(selfSignedCACertificatePK))        //nolint: errcheck
	pk, _ := x509.ParsePKCS1PrivateKey(pkDER.Bytes)                  //nolint: errcheck

	certTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               csrTemplate.Subject,
		DNSNames:              csrTemplate.DNSNames,
		EmailAddresses:        csrTemplate.EmailAddresses,
		IPAddresses:           csrTemplate.IPAddresses,
		URIs:                  csrTemplate.URIs,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	finalCert, _ := x509.CreateCertificate(rand.Reader, &certTemplate, signingCert, csrTemplate.PublicKey, pk) //nolint: errcheck
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{ //nolint: errcheck
		Type:  "CERTIFICATE",
		Bytes: finalCert,
	})

	return certPEM.String()
}
