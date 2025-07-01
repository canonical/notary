package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/canonical/notary/internal/server"
	"go.uber.org/zap"
)

var publicConfig = config.PublicConfigData{
	Port:                  8000,
	PebbleNotifications:   false,
	LoggingLevel:          "debug",
	LoggingOutput:         "stdout",
	EncryptionBackendType: "none",
}

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
	noneEncryptionBackend := encryption_backend.NoEncryptionBackend{}
	s, err := server.New(8000, cert, key, db_path, "example.com", false, l, noneEncryptionBackend, publicConfig)
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
	noneEncryptionBackend := encryption_backend.NoEncryptionBackend{}
	_, err = server.New(8000, cert, []byte{}, "notary.db", "example.com", false, l, noneEncryptionBackend, publicConfig)
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
