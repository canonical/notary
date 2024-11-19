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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	metrics "github.com/canonical/notary/internal/metrics"
)

// TestPrometheusHandler tests that the Prometheus metrics handler responds correctly to an HTTP request.
func TestPrometheusHandler(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.NewMetricsSubsystem(db)

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

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

func initializeTestDB(t *testing.T, db *db.Database) {
	for _, v := range []int{5, 10, 32} {
		csr, cert, ca := generateCertPair(v)
		err := db.CreateCSR(csr)
		if err != nil {
			t.Fatalf("couldn't create test csr: %s", err)
		}
		err = db.AddCertificateChainToCSRbyCSR(csr, fmt.Sprintf("%s%s", cert, ca))
		if err != nil {
			t.Fatalf("couldn't create test cert: %s", err)
		}
	}
}

// TestMetrics tests some of the metrics that we currently collect.
func TestMetrics(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	initializeTestDB(t, db)
	m := metrics.NewMetricsSubsystem(db)
	csrs, _ := db.RetrieveAllCSRs()
	m.GenerateMetrics(csrs)

	request, _ := http.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.Contains(line, "outstanding_certificate_requests ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "0") {
				t.Errorf("outstanding_certificate_requests expected to receive 0")
			}
		} else if strings.Contains(line, "certificate_requests ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificate_requests expected to receive 3")
			}
		} else if strings.Contains(line, "certificates ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates expected to receive 3")
			}
		} else if strings.Contains(line, "certificates_expired ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expired expected to receive 0")
			}
		} else if strings.Contains(line, "certificates_expiring_in_1_day ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expiring_in_1_day expected to receive 0")
			}
		} else if strings.Contains(line, "certificates_expiring_in_7_days ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "1") {
				t.Errorf("certificates_expiring_in_7_days expected to receive 1")
			}
		} else if strings.Contains(line, "certificates_expiring_in_30_days ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "2") {
				t.Errorf("certificates_expiring_in_30_days expected to receive 2")
			}
		} else if strings.Contains(line, "certificates_expiring_in_90_days ") && !strings.HasPrefix(line, "#") {
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates_expiring_in_90_days expected to receive 3")
			}
		}
	}

	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}
}
