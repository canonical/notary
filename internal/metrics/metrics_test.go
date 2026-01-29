package metrics_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/metrics"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

// TestPrometheusHandler tests that the Prometheus metrics handler responds correctly to an HTTP request.
func TestPrometheusHandler(t *testing.T) {
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	db := tu.MustPrepareEmptyDB(t)
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	if !strings.Contains(recorder.Body.String(), "go_goroutines") {
		t.Errorf("handler returned an empty body")
	}
	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// TestMetrics tests some of the metrics that we currently collect.
func TestCertificateMetrics(t *testing.T) {
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	db := tu.MustPrepareEmptyDB(t)
	initializeTestDBWithCerts(t, db)
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()
	csrs, _ := db.ListCertificateRequestWithCertificates()
	m.GenerateCertificateMetrics(csrs)

	request, _ := http.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	expectedMetrics := map[string]struct{}{
		"outstanding_certificate_requests": {},
		"certificate_requests":             {},
		"certificates":                     {},
		"certificates_expired":             {},
		"certificates_expiring_in_1_day":   {},
		"certificates_expiring_in_7_days":  {},
		"certificates_expiring_in_30_days": {},
		"certificates_expiring_in_90_days": {},
	}

	foundMetrics := make(map[string]bool)

	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}

		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "outstanding_certificate_requests ") {
			foundMetrics["outstanding_certificate_requests"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("outstanding_certificate_requests expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificate_requests ") {
			foundMetrics["certificate_requests"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificate_requests expected to receive 3")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates ") {
			foundMetrics["certificates"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates expected to receive 3")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expired ") {
			foundMetrics["certificates_expired"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expired expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_1_day ") {
			foundMetrics["certificates_expiring_in_1_day"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expiring_in_1_day expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_7_days ") {
			foundMetrics["certificates_expiring_in_7_days"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("certificates_expiring_in_7_days expected to receive 1")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_30_days ") {
			foundMetrics["certificates_expiring_in_30_days"] = true
			if !strings.HasSuffix(line, "2") {
				t.Errorf("certificates_expiring_in_30_days expected to receive 2")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_90_days ") {
			foundMetrics["certificates_expiring_in_90_days"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates_expiring_in_90_days expected to receive 3")
			}
		}
	}

	// Verify all expected metrics were found
	for metric := range expectedMetrics {
		if !foundMetrics[metric] {
			t.Errorf("Expected metric %s not found in metrics output", metric)
		}
	}

	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCACertificateMetrics(t *testing.T) {
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	db := tu.MustPrepareEmptyDB(t)
	initializeTestDBWithCaCerts(t, db)
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()
	cas, err := db.ListDenormalizedCertificateAuthorities()
	if err != nil {
		t.Fatalf("couldn't list denormalized certificate authorities: %s", err)
	}
	m.GenerateCACertificateMetrics(cas)

	request, _ := http.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}

	foundMetrics := map[string]bool{
		"enabled_ca_certificates":  false,
		"expired_ca_certificates":  false,
		"disabled_ca_certificates": false,
	}

	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "enabled_ca_certificates ") {
			foundMetrics["enabled_ca_certificates"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("Expected enabled_ca_certificates to be 1, got %s", line)
			}
		} else if strings.HasPrefix(trimmedLine, "expired_ca_certificates ") {
			foundMetrics["expired_ca_certificates"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("Expected expired_ca_certificates to be 0, got %s", line)
			}
		} else if strings.HasPrefix(trimmedLine, "disabled_ca_certificates ") {
			foundMetrics["disabled_ca_certificates"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("Expected disabled_ca_certificates to be 1, got %s", line)
			}
		}
	}

	// Verify all expected metrics were found
	for metric, found := range foundMetrics {
		if !found {
			t.Errorf("Expected metric %s not found in output", metric)
		}
	}
}

// Generates a CSR and Certificate with the given days remaining
func generateCertPair(daysRemaining int) (string, string, string) {
	NotAfterTime := time.Now().AddDate(0, 0, daysRemaining)
	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	csrTemplate := x509.CertificateRequest{}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotAfter:     NotAfterTime,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, certKey)
	caBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	caCertificate, _ := x509.ParseCertificate(caBytes)
	certBytes, _ := x509.CreateCertificate(rand.Reader, &certTemplate, caCertificate, &certKey.PublicKey, caKey)

	var buff bytes.Buffer
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	csr := buff.String()
	buff.Reset()
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	cert := buff.String()
	buff.Reset()
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	ca := buff.String()
	return csr, cert, ca
}

func initializeTestDBWithCerts(t *testing.T, database *db.Database) {
	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "whateverPassword", 0)
	if err != nil {
		t.Fatalf("couldn't create test user: %s", err)
	}
	for _, v := range []int{5, 10, 32} {
		csr, cert, ca := generateCertPair(v)
		csrID, err := database.CreateCertificateRequest(csr, userEmail)
		if err != nil {
			t.Fatalf("couldn't create test csr: %s", err)
		}
		_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRID(csrID), fmt.Sprintf("%s%s", cert, ca))
		if err != nil {
			t.Fatalf("couldn't create test cert: %s", err)
		}
	}
}

func initializeTestDBWithCaCerts(t *testing.T, database *db.Database) {
	// Create user
	userEmail := "testuser@example.com"
	_, err := database.CreateUser(userEmail, "whateverPassword", 0)
	if err != nil {
		t.Fatalf("couldn't create test user: %s", err)
	}
	// create an enabled ca
	_, err = database.CreateCertificateAuthority(tu.RootCACSR, tu.RootCAPrivateKey, tu.RootCACRL, tu.RootCACertificate+"\n"+tu.RootCACertificate, userEmail)
	if err != nil {
		t.Fatalf("couldn't create self signed ca: %s", err)
	}
	// create a pending ca
	_, err = database.CreateCertificateAuthority(tu.IntermediateCACSR, tu.IntermediateCAPrivateKey, "", "", userEmail)
	if err != nil {
		t.Fatalf("couldn't create pending ca: %s", err)
	}
}
