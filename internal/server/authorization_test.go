package server_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalLog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuthorizationNoAuth(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
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

func TestAuthorizationAdminAuthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

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
			path:   "/api/v1/accounts/3",
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
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
		})
	}
}

func TestAuthorizationAdminUnAuthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	nonAdminToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	req, err := http.NewRequest("DELETE", ts.URL+"/api/v1/accounts/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+nonAdminToken)
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    nonAdminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("expected status code %d, got %d", http.StatusForbidden, res.StatusCode)
	}
}

func TestAuthorizationCertificateManagerAuthorized(t *testing.T) {
	ts, logs := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	certManagerToken := tu.MustPrepareAccount(t, ts, "testuser@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "certificate manager can change self password with /me",
			method: "POST",
			path:   "/api/v1/accounts/me/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusCreated,
		},
		{
			desc:   "certificate manager can login with new password",
			method: "POST",
			path:   "/login",
			data:   `{"email":"testuser@canonical.com","password":"BetterPW1!"}`,
			status: http.StatusOK,
		},
		{
			desc:   "certificate manager can create a CA",
			method: "POST",
			path:   "/api/v1/certificate_authorities",
			data:   `{"self_signed":true,"common_name":"abc.com"}`,
			status: http.StatusCreated,
		},
		{
			desc:   "certificate manager can create a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests",
			data:   fmt.Sprintf(`{"csr":%q}`, tu.ExampleCSR),
			status: http.StatusCreated,
		},
		{
			desc:   "certificate manager can read a certificate request",
			method: "GET",
			path:   "/api/v1/certificate_requests/2",
			status: http.StatusOK,
		},
		{
			desc:   "certificate manager can sign a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests/2/sign",
			data:   `{"certificate_authority_id":"1"}`,
			status: http.StatusAccepted,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if tC.desc == "certificate manager can change self password with /me" {
				_ = logs.TakeAll()
			}
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+certManagerToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    certManagerToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
			if tC.desc == "certificate manager can change self password with /me" {
				entries := logs.TakeAll()
				var havePwdChanged, haveUserUpdated bool
				for _, e := range entries {
					if e.LoggerName != "audit" {
						continue
					}
					switch findStringField(e, "event") {
					case "authn_password_change:testuser@canonical.com":
						havePwdChanged = true
					case "user_updated:testuser@canonical.com,password_change":
						haveUserUpdated = true
					}
				}
				if !havePwdChanged {
					t.Errorf("expected PasswordChanged audit entry for self change")
				}
				if !haveUserUpdated {
					t.Errorf("expected UserUpdated audit entry for self change")
				}
			}
		})
	}
}

func TestAuthorizationCertificateManagerUnauthorized(t *testing.T) {
	ts, logs := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	certManagerToken := tu.MustPrepareAccount(t, ts, "whatever@canonical.com", tu.RoleCertificateManager, adminToken)
	client := ts.Client()

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
			_ = logs.TakeAll()
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+certManagerToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    certManagerToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tC.status {
				t.Errorf("expected status code %d, got %d", tC.status, res.StatusCode)
			}
			if tC.status == http.StatusForbidden {
				entries := logs.TakeAll()
				var haveAuthzFail bool
				for _, e := range entries {
					if e.LoggerName != "audit" {
						continue
					}
					if strings.HasPrefix(findStringField(e, "event"), "authz_fail:") {
						haveAuthzFail = true
						break
					}
				}
				if !haveAuthzFail {
					t.Errorf("expected audit authz_fail for %s %s", tC.method, tC.path)
				}
			}
		})
	}
}

func TestAuthorizationCertificateRequestorAuthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	certRequestorToken := tu.MustPrepareAccount(t, ts, "testuser@canonical.com", tu.RoleCertificateRequestor, adminToken)
	client := ts.Client()

	params := tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "abc.com",
	}
	statusCode, _, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, params)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "certificate requestor can change self password with /me",
			method: "POST",
			path:   "/api/v1/accounts/me/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusCreated,
		},
		{
			desc:   "certificate requestor can login with new password",
			method: "POST",
			path:   "/login",
			data:   `{"email":"testuser@canonical.com","password":"BetterPW1!"}`,
			status: http.StatusOK,
		},
		{
			desc:   "certificate requestor can create a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests",
			data:   fmt.Sprintf(`{"csr":%q}`, tu.ExampleCSR),
			status: http.StatusCreated,
		},
		{
			desc:   "certificate requestor can list certificate requests",
			method: "GET",
			path:   "/api/v1/certificate_requests",
			status: http.StatusOK,
		},
		{
			desc:   "certificate requestor can read a certificate request it created",
			method: "GET",
			path:   "/api/v1/certificate_requests/2",
			status: http.StatusOK,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+certRequestorToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    certRequestorToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
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

func TestAuthorizationCertificateRequestorUnauthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	certRequestorToken := tu.MustPrepareAccount(t, ts, "testuser@canonical.com", tu.RoleCertificateRequestor, adminToken)
	client := ts.Client()

	params := tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "abc.com",
	}
	statusCode, _, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, params)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	csrParams := tu.CreateCertificateRequestParams{
		CSR: tu.ExampleCSR,
	}
	statusCode, _, err = tu.CreateCertificateRequest(ts.URL, client, adminToken, csrParams)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "certificate requestor can't change other user password",
			method: "POST",
			path:   "/api/v1/accounts/0/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't see accounts",
			method: "GET",
			path:   "/api/v1/accounts",
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't see specific account",
			method: "GET",
			path:   "/api/v1/accounts/0",
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't create account",
			method: "POST",
			path:   "/api/v1/accounts",
			data:   `{"email":"testuser2@canonical.com","password":"BetterPW1!","role_id":2}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't delete account",
			method: "DELETE",
			path:   "/api/v1/accounts/1",
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't create a CA",
			method: "POST",
			path:   "/api/v1/certificate_authorities",
			data:   `{"self_signed":true,"common_name":"abc.com"}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't read a CA",
			method: "GET",
			path:   "/api/v1/certificate_authorities",
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't delete a CA",
			method: "DELETE",
			path:   "/api/v1/certificate_authorities/1",
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't sign a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests/2/sign",
			data:   `{"certificate_authority_id":"1"}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "certificate requestor can't read a certificate request it didn't create",
			method: "GET",
			path:   "/api/v1/certificate_requests/1",
			status: http.StatusForbidden,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+certRequestorToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    certRequestorToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
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

func TestAuthorizationReadOnlyAuthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	readOnlyToken := tu.MustPrepareAccount(t, ts, "testuser@canonical.com", tu.RoleReadOnly, adminToken)
	client := ts.Client()

	caParams := tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "abc.com",
	}
	statusCode, _, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, caParams)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	certRequestParams := tu.CreateCertificateRequestParams{
		CSR: tu.ExampleCSR,
	}
	statusCode, _, err = tu.CreateCertificateRequest(ts.URL, client, adminToken, certRequestParams)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "certificate requestor can change self password with /me",
			method: "POST",
			path:   "/api/v1/accounts/me/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusCreated,
		},
		{
			desc:   "certificate requestor can login with new password",
			method: "POST",
			path:   "/login",
			data:   `{"email":"testuser@canonical.com","password":"BetterPW1!"}`,
			status: http.StatusOK,
		},
		{
			desc:   "read only user can list CAs",
			method: "GET",
			path:   "/api/v1/certificate_authorities",
			status: http.StatusOK,
		},
		{
			desc:   "read only user can read a CA",
			method: "GET",
			path:   "/api/v1/certificate_authorities/1",
			status: http.StatusOK,
		},
		{
			desc:   "read only user can list certificate requests",
			method: "GET",
			path:   "/api/v1/certificate_requests",
			status: http.StatusOK,
		},
		{
			desc:   "read only user can read a certificate request",
			method: "GET",
			path:   "/api/v1/certificate_requests/2",
			status: http.StatusOK,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+readOnlyToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    readOnlyToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
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

func TestAuthorizationReadOnlyUnauthorized(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	readOnlyToken := tu.MustPrepareAccount(t, ts, "testuser@canonical.com", tu.RoleReadOnly, adminToken)
	client := ts.Client()

	caParams := tu.CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "abc.com",
	}
	statusCode, _, err := tu.CreateCertificateAuthority(ts.URL, client, adminToken, caParams)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	certRequestParams := tu.CreateCertificateRequestParams{
		CSR: tu.ExampleCSR,
	}
	statusCode, _, err = tu.CreateCertificateRequest(ts.URL, client, adminToken, certRequestParams)
	if err != nil {
		t.Fatal(err)
	}

	if statusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, statusCode)
	}

	testCases := []struct {
		desc   string
		method string
		path   string
		data   string
		status int
	}{
		{
			desc:   "read only user can't change other user password",
			method: "POST",
			path:   "/api/v1/accounts/0/change_password",
			data:   `{"password":"BetterPW1!"}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't see accounts",
			method: "GET",
			path:   "/api/v1/accounts",
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't see specific account",
			method: "GET",
			path:   "/api/v1/accounts/0",
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't create account",
			method: "POST",
			path:   "/api/v1/accounts",
			data:   `{"email":"testuser2@canonical.com","password":"BetterPW1!","role_id":2}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't delete account",
			method: "DELETE",
			path:   "/api/v1/accounts/1",
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't create a CA",
			method: "POST",
			path:   "/api/v1/certificate_authorities",
			data:   `{"self_signed":true,"common_name":"abc.com"}`,
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't delete a CA",
			method: "DELETE",
			path:   "/api/v1/certificate_authorities/1",
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't create a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests",
			data:   fmt.Sprintf(`{"csr":%q}`, tu.ExampleCSR),
			status: http.StatusForbidden,
		},
		{
			desc:   "read only user can't sign a certificate request",
			method: "POST",
			path:   "/api/v1/certificate_requests/2/sign",
			data:   `{"certificate_authority_id":"1"}`,
			status: http.StatusForbidden,
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Authorization", "Bearer "+readOnlyToken)
			req.AddCookie(&http.Cookie{
				Name:     server.CookieSessionTokenKey,
				Value:    readOnlyToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
			})
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

func TestAuthorizationFollowsRoleChangeWithoutRelogin(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")
	requestorToken := tu.MustPrepareAccount(t, ts, "requestor@canonical.com", tu.RoleCertificateRequestor, adminToken)

	statusCode, _, err := tu.ListCertificateAuthorities(ts.URL, client, requestorToken)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusForbidden {
		t.Fatalf("requestor listing CAs: got %d, want %d", statusCode, http.StatusForbidden)
	}

	statusCode, me, err := tu.GetMyAccount(ts.URL, client, requestorToken)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("get my account: got %d", statusCode)
	}

	statusCode, _, err = tu.UpdateAccountRole(ts.URL, client, adminToken, me.Data.ID, &tu.UpdateAccountRoleParams{RoleID: tu.RoleCertificateManager})
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusCreated {
		t.Fatalf("update role: got %d, want %d", statusCode, http.StatusCreated)
	}

	statusCode, _, err = tu.ListCertificateAuthorities(ts.URL, client, requestorToken)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("same JWT after role change: got %d, want %d", statusCode, http.StatusOK)
	}
}

func TestAuthorizationMissingRepositoryReturns500(t *testing.T) {
	database := tu.MustPrepareEmptyDB(t)
	core, _ := observer.New(zapcore.InfoLevel)
	appCfg := tu.MustCreateTestAppConfig(t)
	appEnv := tu.MustCreateTestAppEnvironment(t, database)
	appEnv.AuditLogger = internalLog.NewAuditLogger(zap.New(core))
	appEnv.AuthzRepository = nil

	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatalf("Couldn't get server: %s", err)
	}
	ts := httptest.NewTLSServer(srv.Handler)
	t.Cleanup(ts.Close)

	adminToken := tu.MustGetDefaultAdminToken(t, ts)
	req, err := http.NewRequest("GET", ts.URL+"/api/v1/accounts/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("missing authz repository: got %d, want %d", res.StatusCode, http.StatusInternalServerError)
	}
}
