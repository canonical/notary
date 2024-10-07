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
)

type CertificateRequest struct {
	ID          int    `json:"id"`
	CSR         string `json:"csr"`
	Certificate string `json:"certificate"`
}

type GetCertificateRequestResponse struct {
	Result CertificateRequest `json:"result"`
	Error  string             `json:"error,omitempty"`
}

type ListCertificateRequestsResponse struct {
	Error  string               `json:"error,omitempty"`
	Result []CertificateRequest `json:"result"`
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
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests/"+strconv.Itoa(id)+"/certificate/reject", nil)
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
	ts, _, err := setupServer()
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

	t.Run("2. Create certificate request - Bad Request (csr is missing)", func(t *testing.T) {
		createCertificateRequestRequest := CreateCertificateRequestParams{}
		statusCode, createCertResponse, err := createCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if createCertResponse.Error != "csr is missing" {
			t.Fatalf("expected error, got %s", createCertResponse.Error)
		}
	})

	t.Run("3. Create certificate request", func(t *testing.T) {
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

	t.Run("4. List certificate requests - 1 Certificate", func(t *testing.T) {
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

	t.Run("5. Get certificate request", func(t *testing.T) {
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
		if getCertRequestResponse.Result.Certificate != "" {
			t.Fatalf("expected no certificate, got %s", getCertRequestResponse.Result.Certificate)
		}
	})

	t.Run("6. Create identical certificate request", func(t *testing.T) {
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

	t.Run("7. List certificate requests - 1 Certificate", func(t *testing.T) {
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

	t.Run("8. Create another certificate request", func(t *testing.T) {
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

	t.Run("9. List certificate requests - 2 Certificates", func(t *testing.T) {
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

	t.Run("10. Get certificate request 2", func(t *testing.T) {
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
		if getCertRequestResponse.Result.Certificate != "" {
			t.Fatalf("expected no certificate, got %s", getCertRequestResponse.Result.Certificate)
		}
	})

	t.Run("11. Delete certificate request 1", func(t *testing.T) {
		statusCode, err := deleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("12. List certificate requests - 1 Certificate", func(t *testing.T) {
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

	t.Run("13. Delete certificate request 2", func(t *testing.T) {
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
	ts, _, err := setupServer()
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

	t.Run("2. Create Certificate - Bad Request (certificate is missing)", func(t *testing.T) {
		createCertificateRequest := CreateCertificateParams{}
		statusCode, createCertResponse, err := createCertificate(ts.URL, client, adminToken, createCertificateRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
		if createCertResponse.Error != "certificate is missing" {
			t.Fatalf("expected error, got %s", createCertResponse.Error)
		}
	})

	t.Run("3. Create Certificate", func(t *testing.T) {
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

	t.Run("4. Get Certificate", func(t *testing.T) {
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
		if getCertResponse.Result.Certificate == "" {
			t.Fatalf("expected certificate, got empty string")
		}
	})

	t.Run("5. Reject Certificate", func(t *testing.T) {
		statusCode, err := rejectCertificate(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("6. Get Certificate", func(t *testing.T) {
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
		if getCertResponse.Result.Certificate != "rejected" {
			t.Fatalf("expected `rejected` certificate, got %s", getCertResponse.Result.Certificate)
		}
	})

	t.Run("7. Delete Certificate", func(t *testing.T) {
		statusCode, err := deleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("8. Get Certificate", func(t *testing.T) {
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
