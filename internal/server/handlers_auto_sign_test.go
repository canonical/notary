package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
)

func ptr(b bool) *bool { return &b }

func createAutoSignPolicy(url string, client *http.Client, token string, caID int, params server.CreateAutoSignPolicyParams) (int, *tu.APIResponse[server.AutoSignPolicyResponse], error) {
	reqData, err := json.Marshal(params)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", url+"/api/v1/certificate_authorities/"+strconv.Itoa(caID)+"/auto_sign", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var response tu.APIResponse[server.AutoSignPolicyResponse]
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &response, nil
}

func getAutoSignPolicy(url string, client *http.Client, token string, caID int) (int, *tu.APIResponse[server.AutoSignPolicyResponse], error) {
	req, err := http.NewRequest("GET", url+"/api/v1/certificate_authorities/"+strconv.Itoa(caID)+"/auto_sign", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var response tu.APIResponse[server.AutoSignPolicyResponse]
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &response, nil
}

func updateAutoSignPolicy(url string, client *http.Client, token string, caID int, params server.CreateAutoSignPolicyParams) (int, *tu.APIResponse[server.AutoSignPolicyResponse], error) {
	reqData, err := json.Marshal(params)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("PUT", url+"/api/v1/certificate_authorities/"+strconv.Itoa(caID)+"/auto_sign", bytes.NewReader(reqData))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var response tu.APIResponse[server.AutoSignPolicyResponse]
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &response, nil
}

func deleteAutoSignPolicy(url string, client *http.Client, token string, caID int) (int, *tu.APIResponse[struct{}], error) {
	req, err := http.NewRequest("DELETE", url+"/api/v1/certificate_authorities/"+strconv.Itoa(caID)+"/auto_sign", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	var response tu.APIResponse[struct{}]
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return 0, nil, err
	}
	return res.StatusCode, &response, nil
}

func TestCreateAutoSignPolicy(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	// Create a self-signed CA first
	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	caID := caResp.Data.ID

	// Test 1: Create policy for existing CA
	statusCode, createResp, err := createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(true),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, statusCode)
	}
	if createResp.Message != "" {
		t.Fatalf("expected success, got %s", createResp.Message)
	}
	if createResp.Data.PolicyID == 0 {
		t.Fatal("expected policy ID to be set")
	}
	if createResp.Data.CertificateAuthorityID != int64(caID) {
		t.Fatalf("expected CA ID %d, got %d", caID, createResp.Data.CertificateAuthorityID)
	}

	// Test 2: Create policy for non-existent CA
	statusCode, _, err = createAutoSignPolicy(ts.URL, client, adminToken, 999, server.CreateAutoSignPolicyParams{})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
	}

	// Test 3: Create duplicate policy
	statusCode, _, err = createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusConflict {
		t.Fatalf("expected %d, got %d", http.StatusConflict, statusCode)
	}
}

func TestGetAutoSignPolicy(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	caID := caResp.Data.ID

	// Test 4: Get non-existent policy
	statusCode, _, err = getAutoSignPolicy(ts.URL, client, adminToken, caID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
	}

	// Create policy
	_, _, err = createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(true),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test 5: Get existing policy
	statusCode, getResp, err := getAutoSignPolicy(ts.URL, client, adminToken, caID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
	}
	if getResp.Data.Enabled != true {
		t.Fatalf("expected enabled true")
	}
	if getResp.Data.CertificateValidityDays != 90 {
		t.Fatalf("expected validity 90, got %d", getResp.Data.CertificateValidityDays)
	}
}

func TestUpdateAutoSignPolicy(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	caID := caResp.Data.ID

	// Test 6: Update non-existent policy
	statusCode, _, err = updateAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled: ptr(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
	}

	// Create policy
	_, _, err = createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(true),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test 7: Update existing policy
	statusCode, updateResp, err := updateAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(false),
		CertificateValidityDays: 30,
		CertificateLimit:        10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, statusCode)
	}
	if updateResp.Data.Enabled != false {
		t.Fatal("expected enabled false")
	}
	if updateResp.Data.CertificateValidityDays != 30 {
		t.Fatalf("expected validity 30, got %d", updateResp.Data.CertificateValidityDays)
	}
	if updateResp.Data.CertificateLimit != 10 {
		t.Fatalf("expected limit 10, got %d", updateResp.Data.CertificateLimit)
	}
}

func TestDeleteAutoSignPolicy(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	client := ts.Client()

	statusCode, caResp, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "Test CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	caID := caResp.Data.ID

	// Test 8: Delete non-existent policy
	statusCode, _, err = deleteAutoSignPolicy(ts.URL, client, adminToken, caID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("expected %d, got %d", http.StatusNotFound, statusCode)
	}

	// Create policy
	_, _, err = createAutoSignPolicy(ts.URL, client, adminToken, caID, server.CreateAutoSignPolicyParams{
		Enabled:                 ptr(true),
		CertificateValidityDays: 90,
		CertificateLimit:        0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test 9: Delete existing policy
	statusCode, _, err = deleteAutoSignPolicy(ts.URL, client, adminToken, caID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusAccepted {
		t.Fatalf("expected %d, got %d", http.StatusAccepted, statusCode)
	}

	// Verify it's gone
	statusCode, _, err = getAutoSignPolicy(ts.URL, client, adminToken, caID)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusNotFound {
		t.Fatalf("expected %d after delete, got %d", http.StatusNotFound, statusCode)
	}
}