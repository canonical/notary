package server_test

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizationNoAuth(t *testing.T) {
	tempDir := t.TempDir()
	db_path := filepath.Join(tempDir, "db.sqlite3")
	ts, _, err := setupServer(db_path)
	if err != nil {
		t.Fatalf("couldn't create test server: %s", err)
	}
	defer ts.Close()
	client := ts.Client()
	testCases := []struct {
		desc   string
		method string
		path   string
	}{
		{
			desc:   "metrics reachable without auth",
			method: "GET",
			path:   "/metrics",
		},
		{
			desc:   "status reachable without auth",
			method: "GET",
			path:   "/status",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != http.StatusOK {
				t.Errorf("expected status code %d, got %d", http.StatusOK, res.StatusCode)
			}
		})
	}
}

func TestAuthorizationNonAdminAuthorized(t *testing.T) {
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

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "user can change self password with /me",
			method: "POST",
			path:   "/api/v1/accounts/me/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusCreated,
		},
		{
			desc:   "user can login with new password",
			method: "POST",
			path:   "/login",
			data:   `{"username":"testuser","password":"BetterPW1!"}`,
			status: http.StatusOK,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+nonAdminToken)
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
		})
	}
}

func TestAuthorizationNonAdminUnauthorized(t *testing.T) {
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

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "nonadmin can't see accounts",
			method: "GET",
			path:   "/api/v1/accounts",
			data:   "",
			status: http.StatusForbidden,
		},
		{
			desc:   "nonadmin can't delete admin account",
			method: "DELETE",
			path:   "/api/v1/accounts/1",
			data:   "",
			status: http.StatusForbidden,
		},
		{
			desc:   "user can't change admin password",
			method: "POST",
			path:   "/api/v1/accounts/1/change_password",
			data:   `{"password":"Pwnd123!"}`,
			status: http.StatusForbidden,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+nonAdminToken)
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
		})
	}
}

func TestAuthorizationAdminAuthorized(t *testing.T) {
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

	testCases := []struct {
		desc   string
		method string
		path   string
		status int
	}{
		{
			desc:   "admin can see accounts",
			method: "GET",
			path:   "/api/v1/accounts",
			status: http.StatusOK,
		},

		{
			desc:   "admin can delete nonuser",
			method: "DELETE",
			path:   "/api/v1/accounts/2",
			status: http.StatusAccepted,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+adminToken)
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
		})
	}
}

func TestAuthorizationAdminUnAuthorized(t *testing.T) {
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

	req, err := http.NewRequest("DELETE", ts.URL+"/api/v1/accounts/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+nonAdminToken)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("expected status code %d, got %d", http.StatusForbidden, res.StatusCode)
	}
}
