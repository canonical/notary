package server_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"go.uber.org/zap"
)

func TestNewSuccess(t *testing.T) {
	tempDir := t.TempDir()
	db_path := filepath.Join(tempDir, "db.sqlite3")

	certPath := filepath.Join("testdata", "cert.pem")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	keyPath := filepath.Join("testdata", "key.pem")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	s, err := server.New(8000, cert, key, db_path, "example.com", false, l)
	if err != nil {
		t.Errorf("Error occurred: %s", err)
	}
	if s.TLSConfig.Certificates == nil {
		t.Errorf("No certificates were configured for server")
	}
}

func TestInvalidKeyFailure(t *testing.T) {
	certPath := filepath.Join("testdata", "cert.pem")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cannot read file: %s", err)
	}
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	_, err = server.New(8000, cert, []byte{}, "notary.db", "example.com", false, l)
	if err == nil {
		t.Errorf("No error was thrown for invalid key")
	}
}

func createRequestBomb(url string, client *http.Client, adminToken string, certRequest CreateCertificateRequestParams) (int, error) {
	reqData, err := json.Marshal(certRequest)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests", bytes.NewReader(reqData))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
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

func createRequestBombWithCustomHeader(url string, client *http.Client, adminToken string, certRequest CreateCertificateRequestParams, contentLengthHeaderData string) (int, error) {
	reqData, err := json.Marshal(certRequest)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_requests", bytes.NewReader(reqData))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

func TestRequestOverload(t *testing.T) {
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
	t.Run("prepare accounts and tokens", prepareAccounts(ts.URL, client, &adminToken, &nonAdminToken))

	t.Run("throw a valid size string", func(t *testing.T) {
		createCertificateRequestRequest := CreateCertificateRequestParams{CSR: generateRandomString(20)}
		statusCode, err := createRequestBomb(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
	})

	t.Run("throw a bomb", func(t *testing.T) {
		createCertificateRequestRequest := CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBomb(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})

	t.Run("throw a bomb with no content length header", func(t *testing.T) {
		createCertificateRequestRequest := CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBombWithCustomHeader(ts.URL, client, adminToken, createCertificateRequestRequest, "")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})

	t.Run("throw a bomb with fake content length header", func(t *testing.T) {
		createCertificateRequestRequest := CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBombWithCustomHeader(ts.URL, client, adminToken, createCertificateRequestRequest, "2")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})
}

func generateRandomString(kilobytes int) string {
	buf := bytes.NewBuffer(make([]byte, 0, kilobytes*1024))
	for buf.Len() < kilobytes*1024 {
		buf.WriteString("abcdefghijklmnopqrstuvwxyz")
	}
	return buf.String()
}

func TestReconcileCAStatus(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert, err := generateCACertificate(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Failed to generate expired CA data: %s", err)
	}

	validCACSR, validCAKey, validCACRL, validCACert, err := generateCACertificate(time.Now().Add(30 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("Failed to generate valid CA data: %s", err)
	}

	expiredCAID, err := database.CreateCertificateAuthority(expiredCACSR, expiredCAKey, expiredCACRL, expiredCACert+expiredCACert)
	if err != nil {
		t.Fatalf("Failed to create expired CA: %s", err)
	}

	validCAID, err := database.CreateCertificateAuthority(validCACSR, validCAKey, validCACRL, validCACert+validCACert)
	if err != nil {
		t.Fatalf("Failed to create valid CA: %s", err)
	}

	expiredCA, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(expiredCAID))
	if err != nil {
		t.Fatalf("Failed to get expired CA: %s", err)
	}

	validCA, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(validCAID))
	if err != nil {
		t.Fatalf("Failed to get valid CA: %s", err)
	}

	if expiredCA.Status != db.CAActive {
		t.Fatalf("Expected CA status to be 'active', got '%s'", expiredCA.Status)
	}

	if validCA.Status != db.CAActive {
		t.Fatalf("Expected CA status to be 'active', got '%s'", validCA.Status)
	}

	err = server.ReconcileCAStatus(database, zap.NewNop())
	if err != nil {
		t.Fatalf("ReconcileCAStatus failed: %s", err)
	}

	expiredCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(expiredCAID))
	if err != nil {
		t.Fatalf("GetCertificateAuthority failed: %s", err)
	}

	validCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(validCAID))
	if err != nil {
		t.Fatalf("GetCertificateAuthority failed: %s", err)
	}

	if expiredCA.Status != db.CAExpired {
		t.Fatalf("Expected CA status to be 'expired', got '%s'", expiredCA.Status)
	}

	if validCA.Status != db.CAActive {
		t.Fatalf("Expected CA status to be 'active', got '%s'", validCA.Status)
	}
}

func generateCACertificate(notAfter time.Time) (csrPEM string, keyPEM string, crlPEM string, certPEM string, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to generate CA key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Expired Root CA",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CSR: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               csrTemplate.Subject,
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse CA cert: %w", err)
	}

	now := time.Now()
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: []pkix.RevokedCertificate{},
		ThisUpdate:          now.Add(-24 * time.Hour),
		NextUpdate:          now.Add(30 * 24 * time.Hour),
		Number:              big.NewInt(1),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to create CRL: %w", err)
	}

	keyPEM = encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))
	certPEM = encodePEM("CERTIFICATE", caCertDER)
	csrPEM = encodePEM("CERTIFICATE REQUEST", csrDER)
	crlPEM = encodePEM("X509 CRL", crlDER)

	return csrPEM, keyPEM, crlPEM, certPEM, nil
}

func encodePEM(blockType string, derBytes []byte) string {
	var b strings.Builder
	_ = pem.Encode(&b, &pem.Block{Type: blockType, Bytes: derBytes})
	return b.String()
}
