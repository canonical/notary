package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/canonical/notary/internal/server"
)

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

func listCertificateRequests(url string, client *http.Client, adminToken string) (int, *ListCertificateRequestsResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_requests", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

func getCertificateRequest(url string, client *http.Client, adminToken string, id int) (int, *GetCertificateRequestResponse, error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_requests/"+strconv.Itoa(id), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

func createCertificateRequest(url string, client *http.Client, adminToken string, certRequest CreateCertificateRequestParams) (int, *CreateCertificateRequestResponse, error) {
	reqData, err := json.Marshal(certRequest)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

func deleteCertificateRequest(url string, client *http.Client, adminToken string, id int) (int, error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/certificate_requests/"+strconv.Itoa(id), nil)
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

func createCertificate(url string, client *http.Client, adminToken string, cert CreateCertificateParams) (int, *CreateCertificateResponse, error) {
	reqData, err := json.Marshal(cert)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/1/certificate", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

func rejectCertificate(url string, client *http.Client, adminToken string, id int) (int, error) {
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/"+strconv.Itoa(id)+"/reject", nil)
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

// This is an end-to-end test for the certificate requests endpoint.
// The order of the tests is important, as some tests depend on the
// state of the server after previous tests.
func TestCertificateRequestsEndToEnd(t *testing.T) {
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

	t.Run("1. List certificate requests - no requests yet", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateRequests(ts.URL, client, adminToken)
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
			t.Fatalf("expected no certificate requests, got %d", len(listCertRequestsResponse.Result))
		}
	})

	t.Run("2. Create certificate request", func(t *testing.T) {
		csr1Path := filepath.Join("testdata", "csr1.pem")
		csr1, err := os.ReadFile(csr1Path)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		createCertificateRequestRequest := CreateCertificateRequestParams{
			CSR: string(csr1),
		}
		statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCertResponse.Error)
		}
	})

	t.Run("3. List certificate requests - 1 Certificate", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateRequests(ts.URL, client, adminToken)
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
			t.Fatalf("expected 1 certificate request, got %d", len(listCertRequestsResponse.Result))
		}
		if listCertRequestsResponse.Result[0].CertificateChain != "" {
			t.Fatalf("expected empty string for certificate chain, got %s", listCertRequestsResponse.Result[0].CertificateChain)
		}
	})

	t.Run("4. Get certificate request", func(t *testing.T) {
		statusCode, getCertRequestResponse, err := getCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCertRequestResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCertRequestResponse.Error)
		}
		if getCertRequestResponse.Result.ID != 1 {
			t.Fatalf("expected ID 1, got %d", getCertRequestResponse.Result.ID)
		}
		if getCertRequestResponse.Result.CSR == "" {
			t.Fatalf("expected CSR, got empty string")
		}
		if getCertRequestResponse.Result.CertificateChain != "" {
			t.Fatalf("expected no certificate, got %s", getCertRequestResponse.Result.CertificateChain)
		}
	})

	t.Run("5. Create identical certificate request", func(t *testing.T) {
		csr1Path := filepath.Join("testdata", "csr1.pem")
		csr1, err := os.ReadFile(csr1Path)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		createCertificateRequestRequest := CreateCertificateRequestParams{
			CSR: string(csr1),
		}
		statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if createCertResponse.Error != "given csr already recorded" {
			t.Fatalf("expected error, got %s", createCertResponse.Error)
		}
	})

	t.Run("6. List certificate requests - 1 Certificate", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateRequests(ts.URL, client, adminToken)
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
			t.Fatalf("expected 2 certificate requests, got %d", len(listCertRequestsResponse.Result))
		}
	})

	t.Run("7. Create another certificate request", func(t *testing.T) {
		csr2Path := filepath.Join("testdata", "csr2.pem")
		csr2, err := os.ReadFile(csr2Path)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		createCertificateRequestRequest := CreateCertificateRequestParams{
			CSR: string(csr2),
		}
		statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCertResponse.Error)
		}
	})

	t.Run("8. List certificate requests - 2 Certificates", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateRequests(ts.URL, client, adminToken)
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
			t.Fatalf("expected 2 certificate requests, got %d", len(listCertRequestsResponse.Result))
		}
	})

	t.Run("9. Get certificate request 2", func(t *testing.T) {
		statusCode, getCertRequestResponse, err := getCertificateRequest(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCertRequestResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCertRequestResponse.Error)
		}
		if getCertRequestResponse.Result.ID != 2 {
			t.Fatalf("expected ID 2, got %d", getCertRequestResponse.Result.ID)
		}
		if getCertRequestResponse.Result.CSR == "" {
			t.Fatalf("expected CSR, got empty string")
		}
		if getCertRequestResponse.Result.CertificateChain != "" {
			t.Fatalf("expected no certificate, got %s", getCertRequestResponse.Result.CertificateChain)
		}
	})

	t.Run("10. Delete certificate request 1", func(t *testing.T) {
		statusCode, err := deleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("11. List certificate requests - 1 Certificate", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := listCertificateRequests(ts.URL, client, adminToken)
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
			t.Fatalf("expected 1 certificate request, got %d", len(listCertRequestsResponse.Result))
		}
	})

	t.Run("12. Delete certificate request 2", func(t *testing.T) {
		statusCode, err := deleteCertificateRequest(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})
}

// This is an end-to-end test for the certificates endpoint.
// The order of the tests is important, as some tests depend on the
// state of the server after previous tests.
func TestCertificatesEndToEnd(t *testing.T) {
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
	t.Run("1. Create certificate request", func(t *testing.T) {
		csr1Path := filepath.Join("testdata", "csr2.pem")
		csr2, err := os.ReadFile(csr1Path)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		createCertificateRequestRequest := CreateCertificateRequestParams{
			CSR: string(csr2),
		}
		statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCertResponse.Error)
		}
	})

	t.Run("2. Create Certificate", func(t *testing.T) {
		certPath := filepath.Join("testdata", "csr2_cert.pem")
		cert, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		issuerCertPath := filepath.Join("testdata", "issuer_cert.pem")
		issuerCert, err := os.ReadFile(issuerCertPath)
		if err != nil {
			t.Fatalf("cannot read file: %s", err)
		}
		createCertificateRequest := CreateCertificateParams{
			Certificate: fmt.Sprintf("%s\n%s", cert, issuerCert),
		}
		statusCode, createCertResponse, err := createCertificate(ts.URL, client, adminToken, createCertificateRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCertResponse.Error)
		}
	})

	t.Run("3. Get Certificate", func(t *testing.T) {
		statusCode, getCertResponse, err := getCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCertResponse.Error)
		}
		if getCertResponse.Result.CertificateChain == "" {
			t.Fatalf("expected certificate, got empty string")
		}
	})

	t.Run("4. Reject Certificate", func(t *testing.T) {
		statusCode, err := rejectCertificate(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("5. Get Certificate", func(t *testing.T) {
		statusCode, getCertResponse, err := getCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCertResponse.Error)
		}
		if getCertResponse.Result.Status != "Rejected" {
			t.Fatalf("expected `Rejected` status, got %s", getCertResponse.Result.Status)
		}
	})

	t.Run("6. Delete Certificate", func(t *testing.T) {
		statusCode, err := deleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("7. Get Certificate", func(t *testing.T) {
		statusCode, getCertResponse, err := getCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}

		if getCertResponse.Error != "Not Found" {
			t.Fatalf("expected error `Not Found`, got %s", getCertResponse.Error)
		}
	})
}

func TestCreateCertificateRequestInvalidInputs(t *testing.T) {
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

	tests := []struct {
		testName string
		csr      string
		error    string
	}{
		{
			testName: "No csr",
			csr:      "",
			error:    "Invalid request: csr is required",
		},
		{
			testName: "Bad format",
			csr:      "Bad format",
			error:    "Invalid request: could not decode PEM block",
		},
		{
			testName: "Wrong PEM block type",
			csr: `-----BEGIN PRIVATE KEY-----
MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuQ==
-----END PRIVATE KEY-----`,
			error: "Invalid request: expected PEM block type 'CERTIFICATE REQUEST'",
		},
		{
			testName: "Bad CSR content",
			csr: `-----BEGIN CERTIFICATE REQUEST-----
MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuQ==
-----END CERTIFICATE REQUEST-----`,
			error: "Invalid request: could not parse CSR",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			certRequest := CreateCertificateRequestParams{
				CSR: test.csr,
			}
			statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, certRequest)
			if err != nil {
				t.Fatal(err)
			}
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
			}
			if createCertResponse.Error != test.error {
				t.Fatalf("expected error %s, got %s", test.error, createCertResponse.Error)
			}
		})
	}
}

func TestCreateCertificateInvalidInputs(t *testing.T) {
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

	tests := []struct {
		testName    string
		certificate string
		error       string
	}{
		{
			testName:    "No certificate",
			certificate: "",
			error:       "Invalid request: certificate is required",
		},
		{
			testName:    "Bad format",
			certificate: "Bad format",
			error:       "Invalid request: could not decode PEM block",
		},
		{
			testName: "Bad PEM block type",
			certificate: `-----BEGIN PRIVATE KEY-----
MIICfjCCAeegAwIBAgIBADANBgkqhkiG9w0BAQ0FADBcMQswCQYDVQQGEwJjYTEL
-----END PRIVATE KEY-----`,
			error: "Invalid request: expected PEM block type 'CERTIFICATE'",
		},
		{
			testName: "Bad Certificate content",
			certificate: `-----BEGIN CERTIFICATE-----
MIICfjCCAeegAwIBAgIBADANBgkqhkiG9w0BAQ0FADBcMQswCQYDVQQGEwJjYTEL
-----END CERTIFICATE-----`,
			error: "Invalid request: could not parse certificate",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			cert := CreateCertificateParams{
				Certificate: test.certificate,
			}
			statusCode, createCertResponse, err := createCertificate(ts.URL, client, adminToken, cert)
			if err != nil {
				t.Fatal(err)
			}
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
			}
			if createCertResponse.Error != test.error {
				t.Fatalf("expected error %s, got %s", test.error, createCertResponse.Error)
			}
		})
	}
}
