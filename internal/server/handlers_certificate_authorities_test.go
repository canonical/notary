package server_test

import (
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
)

// The order of the tests is important, as some tests depend on the state of the server after previous tests.
func TestSelfSignedCertificateAuthorityEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. List certificate authorities", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 0 {
			t.Fatalf("expected no certificate authorities, got %d", len(listCAsResponse.Result))
		}
	})

	t.Run("2. Create self signed certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: true,

			CommonName:          "Self Signed CA",
			SANsDNS:             "example.com",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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

	t.Run("3. Get all CA's - 1 should be there and enabled", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 1 {
			t.Fatalf("expected 1 certificate authority, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected enabled status, got %v", listCAsResponse.Result[0].Enabled)
		}
		if listCAsResponse.Result[0].CertificatePEM == "" {
			t.Fatalf("expected certificate to have been created, got empty")
		}
	})

	t.Run("4. Make a new Intermediate CA", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: false,

			CommonName:          "Not Self Signed CA",
			SANsDNS:             "examplest.com",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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
	t.Run("5. Get all CA's - 2 should be there, one enabled one pending", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificate authority, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected enabled status, got %v", listCAsResponse.Result[0].Enabled)
		}
		if listCAsResponse.Result[1].Enabled != false {
			t.Fatalf("expected pending status, got %v", listCAsResponse.Result[1].Enabled)
		}
	})

	var IntermediateCACSR string
	t.Run("6. Get CA by ID", func(t *testing.T) {
		statusCode, getCAResponse, err := tu.GetCertificateAuthority(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCAResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCAResponse.Error)
		}
		if getCAResponse.Result.ID != 2 {
			t.Fatalf("expected ID %d, got %d", 2, getCAResponse.Result.ID)
		}
		if getCAResponse.Result.Enabled != false {
			t.Fatalf("expected pending status, got %v", getCAResponse.Result.Enabled)
		}
		if getCAResponse.Result.CSRPEM == "" {
			t.Fatalf("expected CSR to be set")
		}
		if getCAResponse.Result.CertificatePEM != "" {
			t.Fatalf("expected certificate to not be created yet")
		}
		IntermediateCACSR = getCAResponse.Result.CSRPEM
	})

	t.Run("7. Sign the intermediate CA's CSR", func(t *testing.T) {
		signedCert := tu.SignCSR(IntermediateCACSR)
		statusCode, uploadCertificateResponse, err := tu.UploadCertificateToCertificateAuthority(ts.URL, client, adminToken, 2, server.UploadCertificateToCertificateAuthorityParams{CertificateChain: signedCert + tu.SelfSignedCACertificate})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if uploadCertificateResponse.Error != "" {
			t.Fatalf("expected success, got %s", uploadCertificateResponse.Error)
		}
	})
	t.Run("8. Get all CA's - 2 should be there and both enabled", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected first CA to be enabled")
		}
		if listCAsResponse.Result[1].Enabled != true {
			t.Fatalf("expected second CA to be enabled")
		}
	})
	t.Run("9. Make first CA legacy", func(t *testing.T) {
		statusCode, makeLegacyResponse, err := tu.UpdateCertificateAuthority(ts.URL, client, adminToken, 1, tu.UpdateCertificateAuthorityParams{Status: "legacy"})
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
	t.Run("10. Get all CA's - 1 enabled 1 disabled should be there", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != false {
			t.Fatalf("expected first CA to be disabled")
		}
		if listCAsResponse.Result[1].Enabled != true {
			t.Fatalf("expected second CA to be enabled")
		}
	})
	t.Run("11. Delete first CA", func(t *testing.T) {
		statusCode, err := tu.DeleteCertificateAuthority(ts.URL, client, adminToken, 1)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
	})
	t.Run("12. Get all CA's - 1 enabled should be there", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected first CA to be enabled")
		}
	})
}

func TestCreateCertificateAuthorityInvalidInputs(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	tests := []struct {
		testName            string
		selfSigned          bool
		commonName          string
		sansDNS             string
		countryName         string
		stateOrProvinceName string
		localityName        string
		organizationName    string
		organizationalUnit  string
		notValidAfter       string
		error               string
	}{
		{
			testName:            "Invalid Country Name - too long",
			selfSigned:          true,
			commonName:          "canonical.com",
			sansDNS:             "ubuntu.com",
			countryName:         "Canada",
			stateOrProvinceName: "Quebec",
			localityName:        "Montreal",
			organizationName:    "Canonical",
			organizationalUnit:  "Identity",
			notValidAfter:       "2030-01-01T00:00:00Z",

			error: "Invalid request: country_name must be a 2-letter ISO code",
		},
		{
			testName:            "Invalid notValidAfter format - Not RFC3339",
			selfSigned:          true,
			commonName:          "canonical.com",
			sansDNS:             "ubuntu.com",
			countryName:         "CA",
			stateOrProvinceName: "Quebec",
			localityName:        "Montreal",
			organizationName:    "Canonical",
			organizationalUnit:  "Identity",
			notValidAfter:       "2010-01-01 00:00:00Z",

			error: "Invalid request: not_valid_after must be a valid RFC3339 timestamp",
		},
		{
			testName:            "Invalid notValidAfter format - Past time",
			selfSigned:          true,
			commonName:          "canonical.com",
			sansDNS:             "ubuntu.com",
			countryName:         "CA",
			stateOrProvinceName: "Quebec",
			localityName:        "Montreal",
			organizationName:    "Canonical",
			organizationalUnit:  "Identity",
			notValidAfter:       "2010-01-01T00:00:00Z",

			error: "Invalid request: not_valid_after must be a future time",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			createCertificateAuthorityRequest := tu.CreateCertificateAuthorityParams{
				SelfSigned:          test.selfSigned,
				CommonName:          test.commonName,
				SANsDNS:             test.sansDNS,
				CountryName:         test.countryName,
				StateOrProvinceName: test.stateOrProvinceName,
				LocalityName:        test.localityName,
				OrganizationName:    test.organizationName,
				OrganizationalUnit:  test.organizationalUnit,
				NotValidAfter:       test.notValidAfter,
			}
			statusCode, createCertResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificateAuthorityRequest)
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

func TestUploadCertificateToCertificateAuthorityInvalidInputs(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	createCAParams := tu.CreateCertificateAuthorityParams{
		SelfSigned:          false,
		CommonName:          "Intermediate CA",
		SANsDNS:             "intermediate.example.com",
		CountryName:         "US",
		StateOrProvinceName: "California",
		LocalityName:        "San Francisco",
		OrganizationName:    "Canonical",
		OrganizationalUnit:  "Testing",
		NotValidAfter:       time.Now().AddDate(5, 0, 0).Format(time.RFC3339),
	}
	statusCode, _, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCAParams)
	if err != nil {
		t.Fatalf("error creating certificate authority: %v", err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	tests := []struct {
		testName         string
		certificateChain string
		expectedError    string
	}{
		{
			testName:         "Empty certificate chain",
			certificateChain: "",
			expectedError:    "Invalid request: certificate_chain is required",
		},
		{
			testName:         "Non-PEM input",
			certificateChain: "not a pem block",
			expectedError:    "Invalid request: no valid certificate found in certificate_chain",
		},
		{
			testName: "Wrong PEM block type",
			certificateChain: `-----BEGIN PRIVATE KEY-----
MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuQ==
-----END PRIVATE KEY-----`,
			expectedError: "Invalid request: unexpected PEM block type: expected CERTIFICATE",
		},
		{
			testName: "Invalid certificate PEM content",
			certificateChain: `-----BEGIN CERTIFICATE-----
invalid
-----END CERTIFICATE-----`,
			expectedError: "Invalid request: no valid certificate found in certificate_chain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			uploadParams := server.UploadCertificateToCertificateAuthorityParams{
				CertificateChain: tc.certificateChain,
			}
			statusCode, uploadResponse, err := tu.UploadCertificateToCertificateAuthority(ts.URL, client, adminToken, 1, uploadParams)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if statusCode != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
			}
			if uploadResponse.Error != tc.expectedError {
				t.Fatalf("expected error %q, got %q", tc.expectedError, uploadResponse.Error)
			}
		})
	}
}

func TestSignCertificatesEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. List certificate authorities", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 0 {
			t.Fatalf("expected no certificate authorities, got %d", len(listCAsResponse.Result))
		}
	})

	t.Run("2. Create self signed certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: true,

			CommonName:          "Self Signed CA",
			SANsDNS:             "example.com",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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

	t.Run("3. Get all CA's - 1 should be there and enabled", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 1 {
			t.Fatalf("expected 1 certificate authority, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected enabled status, got %v", listCAsResponse.Result[0].Enabled)
		}
		if listCAsResponse.Result[0].CertificatePEM == "" {
			t.Fatalf("expected certificate to have been created, got empty")
		}
	})

	t.Run("4. Make a new Intermediate CA", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: false,

			CommonName:          "Intermediate CA",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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
	t.Run("5. Get all CA's - 2 should be there, one enabled one disabled", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificate authority, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected active status, got %v", listCAsResponse.Result[0].Enabled)
		}
		if listCAsResponse.Result[1].Enabled != false {
			t.Fatalf("expected disabled status, got %v", listCAsResponse.Result[1].Enabled)
		}
	})

	t.Run("6. Get CA by ID", func(t *testing.T) {
		statusCode, getCAResponse, err := tu.GetCertificateAuthority(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if getCAResponse.Error != "" {
			t.Fatalf("expected no error, got %s", getCAResponse.Error)
		}
		if getCAResponse.Result.ID != 2 {
			t.Fatalf("expected ID %d, got %d", 2, getCAResponse.Result.ID)
		}
		if getCAResponse.Result.Enabled != false {
			t.Fatalf("expected pending status, got %v", getCAResponse.Result.Enabled)
		}
		if getCAResponse.Result.CSRPEM == "" {
			t.Fatalf("expected CSR to be set")
		}
		if getCAResponse.Result.CertificatePEM != "" {
			t.Fatalf("expected certificate to not be created yet")
		}
	})
	t.Run("7. Try signing CSR with unsigned intermediate CA - should fail", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: tu.AppleCSR}
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
		statusCode, signCertificateRequestResponse, err := tu.SignCertificateRequest(ts.URL, client, adminToken, 3, server.SignCertificateRequestParams{CertificateAuthorityID: "2"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if signCertificateRequestResponse.Error != "Not Found" {
			t.Fatalf("expected Not Found, got %s", signCertificateRequestResponse.Error)
		}
	})

	t.Run("8. Sign the intermediate CA's CSR", func(t *testing.T) {
		statusCode, uploadCertificateResponse, err := tu.SignCertificateAuthority(ts.URL, client, adminToken, 2, server.SignCertificateAuthorityParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if uploadCertificateResponse.Error != "" {
			t.Fatalf("expected success, got %s", uploadCertificateResponse.Error)
		}
	})
	t.Run("9. Get all CA's - 2 should be there and both active", func(t *testing.T) {
		statusCode, listCAsResponse, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCAsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCAsResponse.Error)
		}
		if len(listCAsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCAsResponse.Result))
		}
		if listCAsResponse.Result[0].Enabled != true {
			t.Fatalf("expected first CA to be active")
		}
		if listCAsResponse.Result[1].Enabled != true {
			t.Fatalf("expected second CA to be active")
		}
		if strings.Count(listCAsResponse.Result[1].CertificatePEM, "BEGIN CERTIFICATE") != 2 {
			t.Fatalf("expected second CA to have a chain with 2 certificates")
		}
	})
	t.Run("10. Create 2nd CSR's", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: tu.StrawberryCSR}
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
	t.Run("11. Try Signing a CA CSR - should fail", func(t *testing.T) {
		statusCode, signCertificateRequestResponse, err := tu.SignCertificateRequest(ts.URL, client, adminToken, 1, server.SignCertificateRequestParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if signCertificateRequestResponse.Error != "Not Found" {
			t.Fatalf("expected not found, got %s", signCertificateRequestResponse.Error)
		}
	})
	t.Run("12. Sign CSRs with each CA", func(t *testing.T) {
		statusCode, signCertificateRequestResponse, err := tu.SignCertificateRequest(ts.URL, client, adminToken, 3, server.SignCertificateRequestParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if signCertificateRequestResponse.Error != "" {
			t.Fatalf("expected success, got %s", signCertificateRequestResponse.Error)
		}
		statusCode, signCertificateRequestResponse, err = tu.SignCertificateRequest(ts.URL, client, adminToken, 4, server.SignCertificateRequestParams{CertificateAuthorityID: "2"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if signCertificateRequestResponse.Error != "" {
			t.Fatalf("expected success, got %s", signCertificateRequestResponse.Error)
		}
	})
	t.Run("13. Validate CSRs", func(t *testing.T) {
		statusCode, listCSRsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if listCSRsResponse.Error != "" {
			t.Fatalf("expected success, got %s", listCSRsResponse.Error)
		}
		if len(listCSRsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCSRsResponse.Result))
		}
		if listCSRsResponse.Result[0].Status != "Active" {
			t.Fatalf("expected first csr to be active, got %s", listCSRsResponse.Result[3].Status)
		}
		if strings.Count(listCSRsResponse.Result[0].CertificateChain, "BEGIN CERTIFICATE") != 2 {
			t.Fatalf("expected first csr to have a chain with 2 certificates")
		}
		if listCSRsResponse.Result[1].Status != "Active" {
			t.Fatalf("expected second csr to be active")
		}
		if strings.Count(listCSRsResponse.Result[1].CertificateChain, "BEGIN CERTIFICATE") != 3 {
			t.Fatalf("expected second csr to have a chain with 3 certificates")
		}
	})
}

func TestUnsuccessfulRequestsMadeToCACSRs(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. Create self signed certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: true,

			CommonName:          "Self Signed CA",
			SANsDNS:             "example.com",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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

	t.Run("2. Create Intermediate certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: false,

			CommonName:          "Not Self Signed CA",
			SANsDNS:             "examplest.com",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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

	t.Run("3. Create CSR", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: tu.AppleCSR}
		statusCode, createCSRResponse, err := tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCSRResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCSRResponse.Error)
		}
	})

	t.Run("4. Get CSRs - only 1 should appear", func(t *testing.T) {
		statusCode, listCertsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if len(listCertsResponse.Result) != 1 {
			t.Fatalf("expected 1 CSR in list, got %d", len(listCertsResponse.Result))
		}
		if listCertsResponse.Error != "" {
			t.Fatalf("expected no error, got %s", listCertsResponse.Error)
		}
		if listCertsResponse.Result[0].CertificateChain != "" {
			t.Fatalf("expected no certificate, got '%s'", listCertsResponse.Result[0].CertificateChain)
		}
	})
	t.Run("5. Get CSR - should fail", func(t *testing.T) {
		statusCode, getCertResponse, err := tu.GetCertificateRequest(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if getCertResponse.Error != "Not Found" {
			t.Fatalf("expected correct error, got %s", getCertResponse.Error)
		}
	})
	t.Run("6. Delete CA CSR - should fail", func(t *testing.T) {
		statusCode, err := tu.DeleteCertificateRequest(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
	})
	t.Run("7. Reject CA CSR - should fail", func(t *testing.T) {
		statusCode, err := tu.RejectCertificate(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
	})
	t.Run("8. Sign CA CSR - should fail", func(t *testing.T) {
		statusCode, signCertificateRequestResponse, err := tu.SignCertificateRequest(ts.URL, client, adminToken, 1, server.SignCertificateRequestParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, statusCode)
		}
		if signCertificateRequestResponse.Error != "Not Found" {
			t.Fatalf("expected correct error, got %s", signCertificateRequestResponse.Error)
		}
	})
}

func TestCertificateRevocationListsEndToEnd(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	t.Run("1. Create self signed certificate authority", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: true,

			CommonName:          "Self Signed CA",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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
	t.Run("2. Create Intermediate CA", func(t *testing.T) {
		createCertificatAuthorityParams := tu.CreateCertificateAuthorityParams{
			SelfSigned: false,

			CommonName:          "Intermediate CA",
			CountryName:         "TR",
			StateOrProvinceName: "Istanbul",
			LocalityName:        "Kadikoy",
			OrganizationName:    "Canonical",
			OrganizationalUnit:  "Identity",
			NotValidAfter:       "2030-01-01T00:00:00Z",
		}
		statusCode, createCAResponse, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, createCertificatAuthorityParams)
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

	t.Run("3. Get CA CRL's. Root CA should have one, Intermediate shouldn't", func(t *testing.T) {
		statusCode, cas, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if len(cas.Result) != 2 {
			t.Fatalf("expected 2 certificate authorities, got %d", len(cas.Result))
		}
		if cas.Result[0].CRL == "" {
			t.Fatalf("expected root CA to have a CRL")
		}
		if cas.Result[1].CRL != "" {
			t.Fatalf("expected intermediate CA to not have a CRL")
		}
	})

	t.Run("4. Sign Intermediate CA", func(t *testing.T) {
		statusCode, signCAResponse, err := tu.SignCertificateAuthority(ts.URL, client, adminToken, 2, server.SignCertificateAuthorityParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if signCAResponse.Error != "" {
			t.Fatalf("expected success, got %s", signCAResponse.Error)
		}
	})

	t.Run("5. Get CA CRL's. Both should have one.", func(t *testing.T) {
		statusCode, cas, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if len(cas.Result) != 2 {
			t.Fatalf("expected 2 certificate authorities, got %d", len(cas.Result))
		}
		if cas.Result[0].CRL == "" {
			t.Fatalf("expected root CA to have a CRL")
		}
		if cas.Result[1].CRL == "" {
			t.Fatalf("expected intermediate CA to have a CRL")
		}
	})

	t.Run("6. Add 2 CSR's and sign them.", func(t *testing.T) {

		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: tu.AppleCSR}
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
		createCertificateRequestRequest = tu.CreateCertificateRequestParams{CSR: tu.StrawberryCSR}
		statusCode, createCertResponse, err = tu.CreateCertificateRequest(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatal(err)
		}
		if statusCode != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
		}
		if createCertResponse.Error != "" {
			t.Fatalf("expected no error, got %s", createCertResponse.Error)
		}
		statusCode, signCertificateRequestResponse, err := tu.SignCertificateRequest(ts.URL, client, adminToken, 3, server.SignCertificateRequestParams{CertificateAuthorityID: "1"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if signCertificateRequestResponse.Error != "" {
			t.Fatalf("expected success, got %s", signCertificateRequestResponse.Error)
		}
		statusCode, signCertificateRequestResponse, err = tu.SignCertificateRequest(ts.URL, client, adminToken, 4, server.SignCertificateRequestParams{CertificateAuthorityID: "2"})
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if signCertificateRequestResponse.Error != "" {
			t.Fatalf("expected success, got %s", signCertificateRequestResponse.Error)
		}
	})
	t.Run("7. Get CSR's. Both should have the correct CRLDistributionPoint extension.", func(t *testing.T) {
		statusCode, listCSRsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if len(listCSRsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCSRsResponse.Result))
		}
		for i, csr := range listCSRsResponse.Result {
			certs, err := db.ParseCertificateChain(csr.CertificateChain)
			if err != nil {
				t.Fatalf("expected no error, got: %s", err)
			}
			if len(certs) != i+2 {
				t.Fatalf("expected %d certificates, got %d", i+2, len(certs))
			}
			if certs[0].CRLDistributionPoints == nil {
				t.Fatalf("expected CRLDistributionPoints to be set")
			}
			if certs[0].CRLDistributionPoints[0] != fmt.Sprintf("https://example.com/api/v1/certificate_authorities/%d/crl", i+1) {
				t.Fatalf("expected CRLDistributionPoint to have the correct URI")
			}
		}
	})

	t.Run("8. Revoke both certificates.", func(t *testing.T) {
		statusCode, response, err := tu.RevokeCertificateRequest(ts.URL, client, adminToken, 3)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected success, got %s", response.Error)
		}
		statusCode, response, err = tu.RevokeCertificateRequest(ts.URL, client, adminToken, 4)
		if err != nil {
			t.Fatal("expected no error, got: ", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected success, got %s", response.Error)
		}
		statusCode, listCSRsResponse, err := tu.ListCertificateRequests(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if len(listCSRsResponse.Result) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(listCSRsResponse.Result))
		}
		for _, csr := range listCSRsResponse.Result {
			if csr.CertificateChain != "" {
				t.Fatalf("expected no certificate, got '%s'", csr.CertificateChain)
			}
		}
		statusCode, cas, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if err != nil {
			t.Fatalf("expected no error checking CA status, got: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d when checking CAs, got %d", http.StatusOK, statusCode)
		}
		if len(cas.Result) != 2 {
			t.Fatalf("expected 2 certificate authorities, got %d", len(cas.Result))
		}
		if cas.Result[0].Enabled != true {
			t.Fatalf("expected root CA to remain active after certificate revocation, got %v", cas.Result[0].Enabled)
		}
		if cas.Result[1].Enabled != true {
			t.Fatalf("expected intermediate CA to remain active after certificate revocation, got %v", cas.Result[1].Enabled)
		}
	})

	t.Run("9. Get both CA's. Each CA should have 1 certificate in their CRL", func(t *testing.T) {
		statusCode, cas, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if len(cas.Result) != 2 {
			t.Fatalf("expected 2 certificate authorities, got %d", len(cas.Result))
		}
		for _, ca := range cas.Result {
			crl, err := db.ParseCRL(ca.CRL)
			if err != nil {
				t.Fatalf("expected no error when parsing CRL, got: %s", err)
			}
			if len(crl.RevokedCertificateEntries) != 1 {
				t.Fatalf("expected 1 revoked certificate, got %d", len(crl.RevokedCertificateEntries))
			}
			if crl.RevokedCertificateEntries[0].SerialNumber == big.NewInt(int64(0)) {
				t.Fatalf("expected a real serial number, got %d", crl.RevokedCertificateEntries[0].SerialNumber)
			}
		}
	})

	t.Run("10. Revoke Intermediate CA", func(t *testing.T) {
		statusCode, response, err := tu.RevokeCertificateAuthority(ts.URL, client, adminToken, 2)
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if statusCode != http.StatusAccepted {
			t.Fatalf("expected status %d, got %d", http.StatusAccepted, statusCode)
		}
		if response.Error != "" {
			t.Fatalf("expected success, got %s", response.Error)
		}
		statusCode, cas, err := tu.ListCertificateAuthorities(ts.URL, client, adminToken)
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if cas.Result[1].Enabled != false {
			t.Fatalf("expected revoked intermediate CA to have pending status")
		}
		if cas.Result[1].CertificatePEM != "" {
			t.Fatalf("expected revoked intermediate CA to not have a certificate")
		}
		crl, err := db.ParseCRL(cas.Result[0].CRL)
		if err != nil {
			t.Fatalf("expected no error when parsing CRL, got: %s", err)
		}
		if len(crl.RevokedCertificateEntries) != 2 {
			t.Fatalf("expected 2 revoked certificates, got %d", len(crl.RevokedCertificateEntries))
		}
	})
	t.Run("11. Get CRL as a non-authenticated user", func(t *testing.T) {
		statusCode, result, err := tu.GetCertificateAuthorityCRLRequest(ts.URL, client, "", 1)
		if err != nil {
			t.Fatalf("expected no error, got: %s", err)
		}
		if statusCode != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, statusCode)
		}
		if result.Error != "" {
			t.Fatalf("expected no error, got %s", result.Error)
		}
		if result.Result.CRL == "" {
			t.Fatalf("expected CRL to be available")
		}
	})
}
