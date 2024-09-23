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

const (
	adminUser              = `{"username": "testadmin", "password": "Admin123"}`
	validUser              = `{"username": "testuser", "password": "userPass!"}`
	invalidUser            = `{"username": "", "password": ""}`
	noPasswordUser         = `{"username": "nopass"}`
	adminUserNewPassword   = `{"id": 1, "password": "newPassword1"}`
	userNewInvalidPassword = `{"id": 1, "password": "password"}`
	userMissingPassword    = `{"id": 1}`
	adminUserWrongPass     = `{"username": "testadmin", "password": "wrongpass"}`
	notExistingUser        = `{"username": "not_existing", "password": "user"}`
)

func TestNotaryUsersHandlers(t *testing.T) {
	testdb, err := db.NewDatabase(":memory:")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.HandlerConfig{}
	env.DB = testdb
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
			desc:     "Retrieve admin user success",
			method:   "GET",
			path:     "/api/v1/accounts/1",
			data:     "",
			auth:     adminToken,
			response: "{\"id\":1,\"username\":\"testadmin\",\"permissions\":1}",
			status:   http.StatusOK,
		},
		{
			desc:     "Retrieve admin user fail",
			method:   "GET",
			path:     "/api/v1/accounts/1",
			data:     "",
			auth:     nonAdminToken,
			response: `{"error":"forbidden: admin access required"}`,
			status:   http.StatusForbidden,
		},
		{
			desc:     "Create no password user success",
			method:   "POST",
			path:     "/api/v1/accounts",
			data:     noPasswordUser,
			auth:     adminToken,
			response: "{\"id\":3,\"password\":",
			status:   http.StatusCreated,
		},
		{
			desc:     "Retrieve normal user success",
			method:   "GET",
			path:     "/api/v1/accounts/2",
			data:     "",
			auth:     adminToken,
			response: "{\"id\":2,\"username\":\"testuser\",\"permissions\":0}",
			status:   http.StatusOK,
		},
		{
			desc:     "Retrieve user failure",
			method:   "GET",
			path:     "/api/v1/accounts/300",
			data:     "",
			auth:     adminToken,
			response: `{"error":"Not Found"}`,
			status:   http.StatusNotFound,
		},
		{
			desc:     "Create user failure",
			method:   "POST",
			path:     "/api/v1/accounts",
			data:     invalidUser,
			auth:     adminToken,
			response: `{"error":"Username is required"}`,
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Change password success",
			method:   "POST",
			path:     "/api/v1/accounts/1/change_password",
			data:     adminUserNewPassword,
			auth:     adminToken,
			response: "1",
			status:   http.StatusOK,
		},
		{
			desc:     "Change password failure no user",
			method:   "POST",
			path:     "/api/v1/accounts/100/change_password",
			data:     adminUserNewPassword,
			auth:     adminToken,
			response: `{"error":"Not Found"}`,
			status:   http.StatusNotFound,
		},
		{
			desc:     "Change password failure missing password",
			method:   "POST",
			path:     "/api/v1/accounts/1/change_password",
			data:     userMissingPassword,
			auth:     adminToken,
			response: "Password is required",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Change password failure bad password",
			method:   "POST",
			path:     "/api/v1/accounts/1/change_password",
			data:     userNewInvalidPassword,
			auth:     adminToken,
			response: "Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Delete user success",
			method:   "DELETE",
			path:     "/api/v1/accounts/2",
			data:     invalidUser,
			auth:     adminToken,
			response: "1",
			status:   http.StatusAccepted,
		},
		{
			desc:     "Delete user failure",
			method:   "DELETE",
			path:     "/api/v1/accounts/2",
			data:     invalidUser,
			auth:     adminToken,
			response: `{"error":"Not Found"}`,
			status:   http.StatusNotFound,
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
