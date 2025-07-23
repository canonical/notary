package testutils

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/server"
)

func MustPrepareServer(t *testing.T) *httptest.Server {
	t.Helper()

	tempDir := t.TempDir()

	notaryServer, err := server.New(&server.ServerOpts{
		Port:                       8000,
		Cert:                       []byte(TestServerCertificate),
		Key:                        []byte(TestServerKey),
		DBPath:                     filepath.Join(tempDir, "db.sqlite3"),
		ExternalHostname:           "example.com",
		PebbleNotificationsEnabled: false,
		Logger:                     logger,
		EncryptionBackend:          NoneEncryptionBackend,
		PublicConfig:               PublicConfig,
	})
	if err != nil {
		t.Fatalf("Couldn't get server: %s", err)
	}
	testServer := httptest.NewTLSServer(notaryServer.Handler)
	t.Cleanup(func() {
		testServer.Close()
	})
	return testServer
}

func MustPrepareAccount(t *testing.T, ts *httptest.Server, email string, roleID RoleID, token string) string {
	t.Helper()

	accountParams := &CreateAccountParams{
		Email:    email,
		Password: "Admin123",
		RoleID:   roleID,
	}
	statusCode, _, err := CreateAccount(ts.URL, ts.Client(), token, accountParams)
	if err != nil {
		t.Fatalf("couldn't create admin account: %s", err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}
	adminLoginParams := &LoginParams{
		Email:    accountParams.Email,
		Password: accountParams.Password,
	}
	statusCode, loginResponse, err := Login(ts.URL, ts.Client(), adminLoginParams)
	if err != nil {
		t.Fatalf("couldn't login admin account: %s", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
	}
	return loginResponse.Result.Token
}

type SuccessResponse struct {
	Message string `json:"message"`
}

type GetAccountResponseResult struct {
	ID     int    `json:"id"`
	Email  string `json:"email"`
	RoleID int    `json:"role_id"`
}

type GetAccountResponse struct {
	Result GetAccountResponseResult `json:"result"`
	Error  string                   `json:"error,omitempty"`
}

type RoleID int

const (
	RoleAdmin                RoleID = 0
	RoleCertificateManager   RoleID = 1
	RoleCertificateRequestor RoleID = 2
	RoleReadOnly             RoleID = 3
)

type CreateAccountParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	RoleID   RoleID `json:"role_id"`
}

type CreateAccountResponseResult struct {
	ID int `json:"id"`
}

type CreateAccountResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

type ChangeAccountPasswordParams struct {
	Password string `json:"password"`
}

type ChangeAccountPasswordResponseResult struct {
	ID int `json:"id"`
}

type ChangeAccountPasswordResponse struct {
	Result ChangeAccountPasswordResponseResult `json:"result"`
	Error  string                              `json:"error,omitempty"`
}

type DeleteAccountResponseResult struct {
	ID int `json:"id"`
}

type DeleteAccountResponse struct {
	Result DeleteAccountResponseResult `json:"result"`
	Error  string                      `json:"error,omitempty"`
}

func GetAccount(url string, client *http.Client, token string, id int) (int, *GetAccountResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/accounts/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var accountResponse GetAccountResponse
	if err := json.NewDecoder(res.Body).Decode(&accountResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &accountResponse, nil
}

func GetMyAccount(url string, client *http.Client, token string) (int, *GetAccountResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/accounts/me", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var accountResponse GetAccountResponse
	if err := json.NewDecoder(res.Body).Decode(&accountResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &accountResponse, nil
}

func CreateAccount(url string, client *http.Client, token string, data *CreateAccountParams) (int, *CreateAccountResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var createResponse CreateAccountResponse
	if err := json.NewDecoder(res.Body).Decode(&createResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &createResponse, nil
}

func ChangeAccountPassword(url string, client *http.Client, token string, id int, data *ChangeAccountPasswordParams) (int, *ChangeAccountPasswordResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/accounts/"+strconv.Itoa(id)+"/change_password", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var changeResponse ChangeAccountPasswordResponse
	if err := json.NewDecoder(res.Body).Decode(&changeResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &changeResponse, nil
}

func DeleteAccount(url string, client *http.Client, token string, id int) (int, *DeleteAccountResponse, error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/accounts/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var deleteResponse DeleteAccountResponse
	if err := json.NewDecoder(res.Body).Decode(&deleteResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &deleteResponse, nil
}

type GetStatusResponseResult struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
}

type GetStatusResponse struct {
	Error  string                  `json:"error,omitempty"`
	Result GetStatusResponseResult `json:"result"`
}

func GetStatus(url string, client *http.Client, token string) (int, *GetStatusResponse, error) {
	req, err := http.NewRequest("GET", url+"/status", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var statusResponse GetStatusResponse
	if err := json.NewDecoder(res.Body).Decode(&statusResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &statusResponse, nil
}

type LoginParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponseResult struct {
	Token string `json:"token"`
}

type LoginResponse struct {
	Result LoginResponseResult `json:"result"`
	Error  string              `json:"error,omitempty"`
}

func Login(url string, client *http.Client, data *LoginParams) (int, *LoginResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/login", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var loginResponse LoginResponse
	if err := json.NewDecoder(res.Body).Decode(&loginResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &loginResponse, nil
}

type GetCertificateRequestResponse struct {
	Result server.CertificateRequest `json:"result"`
	Error  string                    `json:"error,omitempty"`
}

type ListCertificateRequestsResponse struct {
	Error  string                      `json:"error,omitempty"`
	Result []server.CertificateRequest `json:"result"`
}

type CreateCertificateRequestResponse struct {
	ID    int    `json:"id"`
	Error string `json:"error,omitempty"`
}

type CreateCertificateRequestParams struct {
	CSR string `json:"csr"`
}

type CreateCertificateParams struct {
	Certificate string `json:"certificate"`
}

type GetCertificateResponseResult struct {
	Certificate string `json:"certificate"`
}

type GetCertificateResponse struct {
	Result GetCertificateResponseResult `json:"result"`
	Error  string                       `json:"error,omitempty"`
}

type CreateCertificateResponse struct {
	ID    int    `json:"id"`
	Error string `json:"error,omitempty"`
}

func ListCertificateRequests(url string, client *http.Client, token string) (int, *ListCertificateRequestsResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_requests", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var certificateRequestsResponse ListCertificateRequestsResponse
	if err := json.NewDecoder(res.Body).Decode(&certificateRequestsResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &certificateRequestsResponse, nil
}

func GetCertificateRequest(url string, client *http.Client, token string, id int) (int, *GetCertificateRequestResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_requests/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var getCertificateRequestResponse GetCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&getCertificateRequestResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &getCertificateRequestResponse, nil
}

func CreateCertificateRequest(url string, client *http.Client, token string, certRequest CreateCertificateRequestParams) (int, *CreateCertificateRequestResponse, error) {
	reqData, err := json.Marshal(certRequest)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var createCertificateRequestResponse CreateCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateRequestResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &createCertificateRequestResponse, nil
}

func DeleteCertificateRequest(url string, client *http.Client, token string, id int) (int, error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/certificate_requests/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

func CreateCertificate(url string, client *http.Client, token string, cert CreateCertificateParams) (int, *CreateCertificateResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/1/certificate", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var createCertificateResponse CreateCertificateResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &createCertificateResponse, nil
}

func RejectCertificate(url string, client *http.Client, token string, id int) (int, error) {
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/"+strconv.Itoa(id)+"/reject", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
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

type CreateCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func CreateCertificateAuthority(url string, client *http.Client, token string, ca CreateCertificateAuthorityParams) (int, *CreateCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(ca)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func ListCertificateAuthorities(url string, client *http.Client, token string) (int, *ListCertificateAuthoritiesResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func GetCertificateAuthority(url string, client *http.Client, token string, id int) (int, *GetCertificateAuthorityResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

type UpdateCertificateAuthorityParams struct {
	Status string `json:"status,omitempty"`
}

type UpdateCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func UpdateCertificateAuthority(url string, client *http.Client, token string, id int, status UpdateCertificateAuthorityParams) (int, *UpdateCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(status)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("PUT", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func DeleteCertificateAuthority(url string, client *http.Client, token string, id int) (int, error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func UploadCertificateToCertificateAuthority(url string, client *http.Client, token string, id int, cert server.UploadCertificateToCertificateAuthorityParams) (int, *UploadCertificateToCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id)+"/certificate", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

type SignCertificateRequestResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func SignCertificateRequest(url string, client *http.Client, token string, id int, cert server.SignCertificateRequestParams) (int, *SignCertificateRequestResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/"+strconv.Itoa(id)+"/sign", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var signCertificateRequestResponse SignCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&signCertificateRequestResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &signCertificateRequestResponse, nil
}

type SignCertificateAuthorityResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func SignCertificateAuthority(url string, client *http.Client, token string, id int, cert server.SignCertificateAuthorityParams) (int, *SignCertificateAuthorityResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id)+"/sign", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var signCertificateAuthorityResponse SignCertificateAuthorityResponse
	if err := json.NewDecoder(res.Body).Decode(&signCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &signCertificateAuthorityResponse, nil
}

type RevokeCertificateAuthorityCertificateResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func RevokeCertificateAuthority(url string, client *http.Client, token string, id int) (int, *RevokeCertificateAuthorityCertificateResponse, error) {
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id)+"/revoke", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var RevokeCertificateAuthorityResponse RevokeCertificateAuthorityCertificateResponse
	if err := json.NewDecoder(res.Body).Decode(&RevokeCertificateAuthorityResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &RevokeCertificateAuthorityResponse, nil
}

type RevokeCertificateRequestResponse struct {
	Result SuccessResponse `json:"result"`
	Error  string          `json:"error,omitempty"`
}

func RevokeCertificateRequest(url string, client *http.Client, token string, id int) (int, *RevokeCertificateRequestResponse, error) {
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/"+strconv.Itoa(id)+"/certificate/revoke", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var RevokeCertificateRequestResponse RevokeCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&RevokeCertificateRequestResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &RevokeCertificateRequestResponse, nil
}

type GetCRLResponse struct {
	Result server.CRL `json:"result"`
	Error  string     `json:"error,omitempty"`
}

func GetCertificateAuthorityCRLRequest(url string, client *http.Client, token string, id int) (int, *GetCRLResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities/"+strconv.Itoa(id)+"/crl", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var GetCRLResponse GetCRLResponse
	if err := json.NewDecoder(res.Body).Decode(&GetCRLResponse); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &GetCRLResponse, nil
}

// sign a csr with a self signed ca
func SignCSR(csr string) string {
	csrDER, _ := pem.Decode([]byte(csr))                             //nolint: errcheck
	csrTemplate, _ := x509.ParseCertificateRequest(csrDER.Bytes)     //nolint: errcheck
	signingCertDER, _ := pem.Decode([]byte(SelfSignedCACertificate)) //nolint: errcheck
	signingCert, _ := x509.ParseCertificate(signingCertDER.Bytes)    //nolint: errcheck
	pkDER, _ := pem.Decode([]byte(SelfSignedCACertificatePK))        //nolint: errcheck
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

func CreateRequestBombWithCustomHeader(url string, client *http.Client, token string, certRequest CreateCertificateRequestParams, contentLengthHeaderData string) (int, error) {
	reqData, err := json.Marshal(certRequest)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests", bytes.NewReader(reqData))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", contentLengthHeaderData)
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	var createCertificateRequestResponse CreateCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateRequestResponse); err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}
