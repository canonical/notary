package server_test

import (
	"fmt"
	"net/http"
	"testing"

	tu "github.com/canonical/notary/internal/testutils"
)

// This is an end-to-end test for the certificate requests endpoint.
// The order of the tests is important, as some tests depend on the
// state of the server after previous tests.
func TestCertificateRequestsEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "testadmin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. List certificate requests - no requests yet", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
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

		createCertificateRequestRequest := tu.CreateCertificateRequestParams{
			CSR: tu.AppleCSR,
		}
		statusCode, createCertResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
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
		statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
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
		if listCertRequestsResponse.Result[0].Email != "testadmin@canonical.com" {
			t.Fatalf("expected email 'testadmin', got %s", listCertRequestsResponse.Result[0].Email)
		}
	})

	t.Run("4. Get certificate request", func(t *testing.T) {
		statusCode, getCertRequestResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 1)
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
		if getCertRequestResponse.Result.Email != "testadmin@canonical.com" {
			t.Fatalf("expected email 'testadmin', got %s", getCertRequestResponse.Result.Email)
		}
	})

	t.Run("5. Create identical certificate request", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{
			CSR: tu.AppleCSR,
		}
		statusCode, createCertResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
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
		statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
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
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{
			CSR: tu.StrawberryCSR,
		}
		statusCode, createCertResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
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
		statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
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
		statusCode, getCertRequestResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 2)
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
		if getCertRequestResponse.Result.Email != "testadmin@canonical.com" {
			t.Fatalf("expected email 'testadmin', got %s", getCertRequestResponse.Result.Email)
		}
	})

	t.Run("10. Delete certificate request 1", func(t *testing.T) {
		statusCode, err := tu.DeleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("11. List certificate requests - 1 Certificate", func(t *testing.T) {
		statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
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
		statusCode, err := tu.DeleteCertificateRequest(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})
}

// TestListCertificateRequestsRequestorRole tests that a certificate requestor can only view their own requests.
func TestListCertificateRequestsRequestorRole(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "testadmin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// Create a certificate request as the admin
	params1 := tu.CreateCertificateRequestParams{
		CSR: tu.ExampleCSR,
	}
	statusCode, _, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, params1)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	// Create a certificate requestor user
	requestorToken := tu.MustPrepareAccount(t, ts, "requestor@canonical.com", tu.RoleCertificateRequestor, adminToken)

	// Create a certificate request as the requestor
	params2 := tu.CreateCertificateRequestParams{
		CSR: tu.AppleCSR,
	}
	statusCode, _, err = tu.CreateCertificateRequest(ts.URL, client, requestorToken, params2)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	// Create a second certificate request as the requestor
	params3 := tu.CreateCertificateRequestParams{
		CSR: tu.StrawberryCSR,
	}

	statusCode, _, err = tu.CreateCertificateRequest(ts.URL, client, requestorToken, params3)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	// List certificate requests as the requestor
	statusCode, listCertRequestsResponse, err := tu.ListCertificateRequests(ts.URL, client, requestorToken)
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
}

// This is an end-to-end test for the certificates endpoint.
// The order of the tests is important, as some tests depend on the
// state of the server after previous tests.
func TestCertificatesEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. Create certificate request", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{
			CSR: tu.ExampleCSR,
		}
		statusCode, createCertResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
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
		createCertificateRequest := tu.CreateCertificateParams{
			Certificate: fmt.Sprintf("%s\n%s", tu.ExampleCSRCertificate, tu.ExampleCSRIssuerCertificate),
		}
		statusCode, createCertResponse, err := tu.CreateCertificate(ts.URL, client, adminToken, createCertificateRequest)
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
		statusCode, getCertResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 1)
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
		statusCode, err := tu.RejectCertificate(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("5. Get Certificate", func(t *testing.T) {
		statusCode, getCertResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 1)
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
		statusCode, err := tu.DeleteCertificateRequest(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
	})

	t.Run("7. Get Certificate", func(t *testing.T) {
		statusCode, getCertResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 1)
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
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

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
			certRequest := tu.CreateCertificateRequestParams{
				CSR: test.csr,
			}
			statusCode, createCertResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, certRequest)
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
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

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
			cert := tu.CreateCertificateParams{
				Certificate: test.certificate,
			}
			statusCode, createCertResponse, err := tu.CreateCertificate(ts.URL, client, adminToken, cert)
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
