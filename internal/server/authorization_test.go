package server_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
)

func TestAuthorization(t *testing.T) {
	testdb, err := db.NewDatabase(":memory:")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.HandlerConfig{}
	env.DB = testdb
	env.JWTSecret = []byte("secret")
	ts := httptest.NewTLSServer(server.NewHandler(env))
	defer ts.Close()

	client := ts.Client()
	var adminToken string
	var nonAdminToken string
	t.Run("prepare user accounts and tokens", prepareUserAccounts(ts.URL, client, &adminToken, &nonAdminToken))

	testCases := []struct {
		desc     string
		method   string
		path     string
		data     string
		auth     string
		response string
		status   int
	}{
		{
			desc:     "metrics reachable without auth",
			method:   "GET",
			path:     "/metrics",
			data:     "",
			auth:     "",
			response: "# HELP certificate_requests Total number of certificate requests",
			status:   http.StatusOK,
		},
		{
			desc:     "status reachable without auth",
			method:   "GET",
			path:     "/status",
			data:     "",
			auth:     "",
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "missing endpoints produce 404",
			method:   "GET",
			path:     "/this/path/does/not/exist",
			data:     "",
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusNotFound,
		},
		{
			desc:     "nonadmin can't see accounts",
			method:   "GET",
			path:     "/api/v1/accounts",
			data:     "",
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusForbidden,
		},
		{
			desc:     "admin can see accounts",
			method:   "GET",
			path:     "/api/v1/accounts",
			data:     "",
			auth:     adminToken,
			response: `[{"id":1,"username":"testadmin","permissions":1},{"id":2,"username":"testuser","permissions":0}]`,
			status:   http.StatusOK,
		},
		{
			desc:     "nonadmin can't delete admin account",
			method:   "DELETE",
			path:     "/api/v1/accounts/1",
			data:     "",
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusForbidden,
		},
		{
			desc:     "user can't change admin password",
			method:   "POST",
			path:     "/api/v1/accounts/1/change_password",
			data:     `{"password":"Pwnd123!"}`,
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusForbidden,
		},
		{
			desc:     "user can change self password with /me",
			method:   "POST",
			path:     "/api/v1/accounts/me/change_password",
			data:     `{"password":"BetterPW1!"}`,
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "user can login with new password",
			method:   "POST",
			path:     "/login",
			data:     `{"username":"testuser","password":"BetterPW1!"}`,
			auth:     nonAdminToken,
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "admin can't delete itself",
			method:   "DELETE",
			path:     "/api/v1/accounts/1",
			data:     "",
			auth:     adminToken,
			response: `{"error":"deleting an Admin account is not allowed."}`,
			status:   http.StatusBadRequest,
		},
		{
			desc:     "admin can delete nonuser",
			method:   "DELETE",
			path:     "/api/v1/accounts/2",
			data:     "",
			auth:     adminToken,
			response: "1",
			status:   http.StatusAccepted,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			req.Header.Add("Authorization", "Bearer "+tC.auth)
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resBody, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status || !strings.Contains(string(resBody), tC.response) {
				t.Errorf("expected response did not match.\nExpected vs Received status code: %d vs %d\nExpected vs Received body: \n%s\nvs\n%s\n", tC.status, res.StatusCode, tC.response, string(resBody))
			}
			if tC.desc == "Create no password user success" {
				match, _ := regexp.MatchString(`"password":"[!-~]{16}"`, string(resBody))
				if !match {
					t.Errorf("password does not match expected format or length: got %s", string(resBody))
				}
			}
		})
	}
}
