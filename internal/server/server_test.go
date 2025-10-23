package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
)

func TestNewSuccess(t *testing.T) {
	db := tu.MustPrepareEmptyDB(t)
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	s, err := server.New(&server.ServerOpts{
		Port:                      8000,
		TLSCertificate:            []byte(tu.TestServerCertificate),
		TLSPrivateKey:             []byte(tu.TestServerKey),
		Database:                  db,
		ExternalHostname:          "example.com",
		EnablePebbleNotifications: false,
		Logger:                    l,
		PublicConfig:              &tu.PublicConfig,
	})
	if err != nil {
		t.Errorf("Error occurred: %s", err)
	}
	if s.TLSConfig.Certificates == nil {
		t.Errorf("No certificates were configured for server")
	}
}

func TestInvalidKeyFailure(t *testing.T) {
	db := tu.MustPrepareEmptyDB(t)
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	_, err = server.New(&server.ServerOpts{
		Port:                      8000,
		Database:                  db,
		TLSCertificate:            []byte(tu.TestServerCertificate),
		TLSPrivateKey:             []byte{},
		ExternalHostname:          "example.com",
		EnablePebbleNotifications: false,
		Logger:                    l,
		PublicConfig:              &tu.PublicConfig,
	})
	if err == nil {
		t.Errorf("No error was thrown for invalid key")
	}
}

func TestRequestOverload(t *testing.T) {
	ts := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	t.Run("throw a valid size string", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: generateRandomString(20)}
		statusCode, err := createRequestBomb(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}

		if statusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, statusCode)
		}
	})

	t.Run("throw a bomb", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBomb(ts.URL, client, adminToken, createCertificateRequestRequest)
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})

	t.Run("throw a bomb with no content length header", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBombWithCustomHeader(ts.URL, client, adminToken, createCertificateRequestRequest, "")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})

	t.Run("throw a bomb with fake content length header", func(t *testing.T) {
		createCertificateRequestRequest := tu.CreateCertificateRequestParams{CSR: generateRandomString(200)}
		statusCode, err := createRequestBombWithCustomHeader(ts.URL, client, adminToken, createCertificateRequestRequest, "2")
		if err != nil {
			t.Fatalf("couldn't get status: %s", err)
		}
		if statusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, statusCode)
		}
	})
}

func createRequestBomb(url string, client *http.Client, adminToken string, certRequest tu.CreateCertificateRequestParams) (int, error) {
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
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	var createCertificateRequestResponse tu.CreateCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateRequestResponse); err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

func createRequestBombWithCustomHeader(url string, client *http.Client, adminToken string, certRequest tu.CreateCertificateRequestParams, contentLengthHeaderData string) (int, error) {
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
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	var createCertificateRequestResponse tu.CreateCertificateRequestResponse
	if err := json.NewDecoder(res.Body).Decode(&createCertificateRequestResponse); err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

func generateRandomString(kilobytes int) string {
	buf := bytes.NewBuffer(make([]byte, 0, kilobytes*1024))
	for buf.Len() < kilobytes*1024 {
		buf.WriteString("abcdefghijklmnopqrstuvwxyz")
	}
	return buf.String()
}
