package server_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	server "github.com/canonical/notary/internal/api"
	"github.com/canonical/notary/internal/certdb"
	"github.com/golang-jwt/jwt"
)

const (
	AppleCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICsTCCAZkCAQAwbDELMAkGA1UEBhMCQ0ExFDASBgNVBAgMC05vdmEgU2NvdGlh
MRAwDgYDVQQHDAdIYWxpZmF4MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQxEjAQBgNVBAMMCWFwcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOhDSpNbeFiXMQzQcobExHqYMEGzqpX8N9+AR6/HPZWBybgx1hr3
ejqsKornzpVph/dO9UC7O9aBlG071O9VQGHt3OU3rkZIk2009vYwLuSrAlJtnUne
p7KKn2lZGvh7jVyZE5RkS0X27vlT0soANsmcVq/82VneHrF/nbDcK6DOjQpS5o5l
EiNk2CIpYGUkw3WnQF4pBk8t4bNOl3nfpaAOfnmNuBX3mWyfPnaKMCENMpDqL9FR
V/O5bIPLmyH30OHUEJUkWOmFt9GFi+QfMoM0fR34KmRbDz79hZZb/yVPZZJl7l6i
FWXkNR3gxdEnwCZkTgWk5OqS9dCJOtsDE8ECAwEAAaAAMA0GCSqGSIb3DQEBCwUA
A4IBAQCqBX5WaNv/HjkzAyNXYuCToCb8GjmiMqL54t+1nEI1QTm6axQXivEbQT3x
GIh7uQYC06wHE23K6Znc1/G+o3y6lID07rvhBNal1qoXUiq6CsAqk+DXYdd8MEh5
joerEedFqcW+WTUDcqddfIyDAGPqrM9j6/E+aFYyZjJ/xRuMf1zlWMljRiwj1NI9
NxqjsYYQ3zxfUjv8gxXm0hN8Up1O9saoEF+zbuWNdiUWd6Ih3/3u5VBNSxgVOrDQ
CeXyyzkMx1pWTx0rWa7NSa+DMKVVzv46pck/9kLB4gPL8zqvIOMQsf74N0VcbVfd
9jQR8mPXQYPUERl1ZhNrkzkyA0kd
-----END CERTIFICATE REQUEST-----`
	BananaCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICrjCCAZYCAQAwaTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYD
VQQHDAlOYXJsaWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK+vJMxO1GTty09/E4M/RbTCPABleCuYc/uzj72KWaIvoDaanuJ4NBWM
2aUiepxWdMNTR6oe31gLq4agLYT309tXwCeBLQnOxvBFWONmBG1qo0fQkvT5kSoq
AO29D7hkQ0gVwg7EF3qOd0JgbDm/yvexKpYLVvWMQAngHwZRnd5vHGk6M3P7G4oG
mIj/CL2bF6va7GWODYHb+a7jI1nkcsrk+vapc+doVszcoJ+2ryoK6JndOSGjt9SD
uxulWZHQO32XC0btyub63pom4QxRtRXmb1mjM37XEwXJSsQO1HOnmc6ycqUK53p0
jF8Qbs0m8y/p2NHFGTUfiyNYA3EdkjUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IB
AQA+hq8kS2Y1Y6D8qH97Mnnc6Ojm61Q5YJ4MghaTD+XXbueTCx4DfK7ujYzK3IEF
pH1AnSeJCsQeBdjT7p6nv5GcwqWXWztNKn9zibXiASK/yYKwqvQpjSjSeqGEh+Sa
9C9SHeaPhZrJRj0i3NkqmN8moWasF9onW6MNKBX0B+pvBB+igGPcjCIFIFGUUaky
upMXY9IG3LlWvlt+HTfuMZV+zSOZgD9oyqkh5K9XRKNq/mnNz/1llUCBZRmfeRBY
+sJ4M6MJRztiyX4/Fjb8UHQviH931rkiEGtG826IvWIyiRSnAeE8B/VzL0GlT9Zq
ge6lFRxB1FlDuU4Blef8FnOI
-----END CERTIFICATE REQUEST-----`
	StrawberryCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICrzCCAZcCAQAwajELMAkGA1UEBhMCSVQxDzANBgNVBAgMBlBhZG92YTEOMAwG
A1UEBwwFUGFkdWExITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEX
MBUGA1UEAwwOc3RyYXdiZXJyeS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDXXHpy+3LLRCImyEQitM9eUdgYkexLz2PcAf89tTpkpt3L1woJw0bv
+YR80UcR2Pg+7uUVm4XSKFvcdyWg8yADHIDDZkEmKFEbrOLUsWWTQEsCpFt5MU4u
6YnYXV0YflPXmRsJRd90NOen+wlM2ajK1gGTtLPdJ6axz15LdcT2uXXIvWhncjgL
CvVpd/x44AMxD/BPf/d27VO5hEjxR//DtcOmS/jA+Zf1+dyIAWs2LH+ctsaPLOcg
1rBiRrHtGL8wmPwgwK9b+QLiq9Ik+dx1Jl6BvC36LRk2CxTxfZ6e4UdYVhtnjMW2
VEUAVg9LtowvXTexESUv6Mh4uQF6pW5ZAgMBAAGgADANBgkqhkiG9w0BAQsFAAOC
AQEAW40HaxjVSDNKeWJ8StWGfstdvk3dwqjsfLgmnBBZSLcGppYEnnRlJxhMJ9Ks
x2IYw7wJ55kOJ7V+SunKPPoY+7PwNDV9Llxp58vvE8CFnOc3WcL9pA2V5LbTXwtT
R7jID5GZjOv0bn3x1WXuKVW5tkYdT6sW14rfGut1T+r1kYls+JQ5ap+BzfMtThZz
38PCnEMmSo0/KmgUu5/LakPoy3JPaFB0bCgViZSWlxiSR44YZPsVaRL8E7Zt/qjJ
glRL/48q/tORtxv18/Girl6oiQholkADaH3j2gB3t/fCLp8guAVLWB9DzhwrqWwP
GFl9zB5HDoij2l0kHrb44TuonQ==
-----END CERTIFICATE REQUEST-----`
	BananaCert = `-----BEGIN CERTIFICATE-----
MIIEUTCCAjkCFE8lmuBE85/RPw2M17Kzl93O+9IIMA0GCSqGSIb3DQEBCwUAMGEx
CzAJBgNVBAYTAlRSMQ4wDAYDVQQIDAVJem1pcjESMBAGA1UEBwwJTmFybGlkZXJl
MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxCzAJBgNVBAMMAm1l
MB4XDTI0MDYyODA4NDIyMFoXDTI1MDYyODA4NDIyMFowaTELMAkGA1UEBhMCVFIx
DjAMBgNVBAgMBUl6bWlyMRIwEAYDVQQHDAlOYXJsaWRlcmUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+vJMxO1GTty09/E4M/RbTCPABl
eCuYc/uzj72KWaIvoDaanuJ4NBWM2aUiepxWdMNTR6oe31gLq4agLYT309tXwCeB
LQnOxvBFWONmBG1qo0fQkvT5kSoqAO29D7hkQ0gVwg7EF3qOd0JgbDm/yvexKpYL
VvWMQAngHwZRnd5vHGk6M3P7G4oGmIj/CL2bF6va7GWODYHb+a7jI1nkcsrk+vap
c+doVszcoJ+2ryoK6JndOSGjt9SDuxulWZHQO32XC0btyub63pom4QxRtRXmb1mj
M37XEwXJSsQO1HOnmc6ycqUK53p0jF8Qbs0m8y/p2NHFGTUfiyNYA3EdkjUCAwEA
ATANBgkqhkiG9w0BAQsFAAOCAgEAVZJZD0/ojZSOVIesZvrjLG0agSp0tsXY+hEt
I/knpYLvRcAd8b3Jx9gk+ug+FwDQ4IBIkTX18qhK2fgVUuMR/ubfpQeCMbp64N3Q
kmN/E1eu0bl6hhHAL7jEbi0DE3vAN9huQxAIu5pCyLvZIrPJtvuyj2jOpJBZwGoP
539lfEM++XALzI4qKQ6Z0a0rJZ4HoruKiYwEFZ7VkmRLD0uef6NMZRqa/Vx+o0uT
1TjH4AeDDmJmP/aHlHbpXkHQ9h9rfTa6Qbypo+T9pGDhd02O1tEqrHfiQyNWJxb0
rbR+owT32iCfayzKKqhmAYSF2d9XKWEhulgxWDaXgvUbq4Y+fgfU2qMVz5uusTDh
a9Mp9dsYWySWEUcEa4v2w6FfaaVXE1S9ubm+HoIVtotuutL5fn86q19pAAePYjLQ
ybiETp5LU3chuYmMlCiDRNGHYhN5nvGcttqRdWIBe454RRPNo4iGVl13l6aG8rmI
xDfk5lIwObalbELv+mEIGI1j/j4//nJFXByxlLHm5/BF8rmvHDj1aPtPRw9DLgSX
ejhjjec1xnkBR+JF0g474hLdPjCnA0aqLQInZbjJJm5iXzyXBg1cy7KvIBy3ZkrR
Pp7ObjaWxjCT3O6nEH3w6Ozsyg2cHXQIdVXLvNnV1bxUbPnfhQosKGKgU6s+lcLM
SRhHB2k=
-----END CERTIFICATE-----`
	IssuerCert = `-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIUDjtO3bEluUX3tzvrckATlycRVfwwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYDVQQHDAlOYXJs
aWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UE
AwwCbWUwHhcNMjQwNjI4MDYwNTQ5WhcNMzQwNjI2MDYwNTQ5WjBhMQswCQYDVQQG
EwJUUjEOMAwGA1UECAwFSXptaXIxEjAQBgNVBAcMCU5hcmxpZGVyZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQswCQYDVQQDDAJtZTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJU+5YaFlpn+bWvVri5L6EkmbAPuavsI
/KXY7ufRmc5qb08o1na9lLJ/7TuMD4K36Idnq20n1JohSlrdymBpNZ8O3m5fYYtk
hx5WADlBZsKnC5aZJIChEb4bYcOFLP+d3PooVsAKBxW0Q6TECviQcK7GxaxEZw0L
7FRhX2c9+CxbvRGP6OGVggXZxwkZik/JJ9aym+fltt9QvlxQVBq/GlFYZYC+H8jV
Z6RnUjugnWcTm9PAsQ6+EHEevAW+dWaDP+gr9AgKKz1EXbc1mVKAVOLHjb+Ue7RC
vFoar/YxYIszD58dOSB/GuAxn+JAjWbnOu7jeX3XeWlKOagUJF9L9TgMIUWdiuJG
8Uu/kK2MjyRFdT8opnPFAXrK7vSuMBzhRtswAlWc8xoZWeSQF+NpjU+swbg8ySYT
LfZxVB+s/ftxnGU3RM/RWdbZhb0DAuIBsFAGCbnj+Q61/cK4i58JVjUqzLk+XOwR
55LAyS0Y5pj9jDc5mqvS0z7ot7s2OBM1+o8e3KJgdMSXorYkv3toHMGEIUmPQZCX
JtRCjFNgnoWeLDc+oLiN6BlPx7bS4MDN9tMPCJwF6vnxFzLAzdRqY3D7uRS3chsx
7ClMR9MDsSxplC7tptXgv8UTzh1XZjWGCeZq0Gbe927Hmwy2q8k/BFwnR4PIVSiE
7YAZPb0CPmrfAgMBAAGjUzBRMB0GA1UdDgQWBBRgLXukRHTovOG6g9Z5eCaeh6Sx
aTAfBgNVHSMEGDAWgBRgLXukRHTovOG6g9Z5eCaeh6SxaTAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4ICAQA9TpgTrGmnyxKB2ne76LNQadiijVPpS6/U
OPFAX4EPJ0V5DhDreJjsZJC6Is2Q9+qsPpn/nlW7bvZUVHGodUKcE+TQWFiMtLvu
8ifzk8x1R46aqhTyxb7WBBFfvbvdmlEENKTmTS6A/C3nYgmkfk5N7x84iTowmsVl
Yzz9iRzxkqQ+mU3L2/Sp5nXPYWfzV9WXIJdxWcot7f4CJ79eVFu4D9hYfzcPQ9P9
0qCBRbH/01D2E/3uTHhZPPmK2Tp1ao5SuGLppjMPX8VWVL5CMTXOj+1LF0nJJc/J
9MrqXwtlLyKGP6HX8qALbaXwcv7db6bF+aEsgWmIEB+0ecGk9IR3XQn7I379CO3v
J2oUCZ++lV9e2tcRehUprE1v8i+DFhPtS1iNjrO7KnDYkXimR5zI+3sGFI9/9wY0
4PAV/roZFiEJHe5kA49vwIihJaDgy/SPIYgG/vhdj+WeIbi1ilEi12ou7VF0tyiE
j3eXaMAL8EAKxCUZbXcuwmK9qistAYXBFFEK9M08FwLH8HM4LoPjshMg3II9Ncs8
p3to8U99/ZeFbJRzEUF9poZ7VwxBEcgfWD1RV0+gNLC3Au2yuc4C3anknOv7Db/r
jdzVA8yTI8cZ/RtRohp5H/s+j2tcdfB3Zt+wfS4nLxqN/kf7qv2VSdPbXyTyz/ft
btZkbfdL5A==
-----END CERTIFICATE-----
`
)

var (
	expectedGetAllCertsResponseBody1 = fmt.Sprintf("[{\"id\":1,\"csr\":\"%s\",\"certificate\":\"\"}]", trimmed(AppleCSR))
	expectedGetAllCertsResponseBody2 = fmt.Sprintf("[{\"id\":1,\"csr\":\"%s\",\"certificate\":\"\"},{\"id\":2,\"csr\":\"%s\",\"certificate\":\"\"}]", trimmed(AppleCSR), trimmed(BananaCSR))
	expectedGetAllCertsResponseBody3 = fmt.Sprintf("[{\"id\":2,\"csr\":\"%s\",\"certificate\":\"%s\\n%s\"},{\"id\":3,\"csr\":\"%s\",\"certificate\":\"\"},{\"id\":4,\"csr\":\"%s\",\"certificate\":\"rejected\"}]", trimmed(BananaCSR), trimmed(BananaCert), trimmed(IssuerCert), trimmed(StrawberryCSR), trimmed(AppleCSR))
	expectedGetAllCertsResponseBody4 = fmt.Sprintf("[{\"id\":2,\"csr\":\"%s\",\"certificate\":\"\"},{\"id\":3,\"csr\":\"%s\",\"certificate\":\"\"},{\"id\":4,\"csr\":\"%s\",\"certificate\":\"rejected\"}]", trimmed(BananaCSR), trimmed(StrawberryCSR), trimmed(AppleCSR))
	expectedGetCertReqResponseBody1  = fmt.Sprintf("{\"id\":2,\"csr\":\"%s\",\"certificate\":\"\"}", trimmed(BananaCSR))
	expectedGetCertReqResponseBody2  = fmt.Sprintf("{\"id\":4,\"csr\":\"%s\",\"certificate\":\"\"}", trimmed(AppleCSR))
	expectedGetCertReqResponseBody3  = fmt.Sprintf("{\"id\":2,\"csr\":\"%s\",\"certificate\":\"%s\\n%s\"}", trimmed(BananaCSR), trimmed(BananaCert), trimmed(IssuerCert))
	expectedGetCertReqResponseBody4  = fmt.Sprintf("{\"id\":2,\"csr\":\"%s\",\"certificate\":\"\"}", trimmed(BananaCSR))
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

func TestNotaryCertificatesHandlers(t *testing.T) {
	testdb, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	ts := httptest.NewTLSServer(server.NewNotaryRouter(env))
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
		response string
		status   int
	}{
		{
			desc:     "1: healthcheck success",
			method:   "GET",
			path:     "/status",
			data:     "",
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "2: empty get csrs success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: "null",
			status:   http.StatusOK,
		},
		{
			desc:     "3: post csr1 fail",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     "this is very clearly not a csr",
			response: "error: csr validation failed: PEM Certificate Request string not found or malformed",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "4: post csr1 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     AppleCSR,
			response: "1",
			status:   http.StatusCreated,
		},
		{
			desc:     "5: get csrs 1 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody1,
			status:   http.StatusOK,
		},
		{
			desc:     "6: post csr2 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     BananaCSR,
			response: "2",
			status:   http.StatusCreated,
		},
		{
			desc:     "7: get csrs 2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody2,
			status:   http.StatusOK,
		},
		{
			desc:     "8: post csr2 fail",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     BananaCSR,
			response: "error: given csr already recorded",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "9: post csr3 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     StrawberryCSR,
			response: "3",
			status:   http.StatusCreated,
		},
		{
			desc:     "10: delete csr1 success",
			method:   "DELETE",
			path:     "/api/v1/certificate_requests/1",
			data:     "",
			response: "1",
			status:   http.StatusAccepted,
		},
		{
			desc:     "11: delete csr5 fail",
			method:   "DELETE",
			path:     "/api/v1/certificate_requests/5",
			data:     "",
			response: "error: id not found",
			status:   http.StatusNotFound,
		},
		{
			desc:     "12: get csr1 fail",
			method:   "GET",
			path:     "/api/v1/certificate_requests/1",
			data:     "",
			response: "error: id not found",
			status:   http.StatusNotFound,
		},
		{
			desc:     "13: get csr2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/2",
			data:     "",
			response: expectedGetCertReqResponseBody1,
			status:   http.StatusOK,
		},
		{
			desc:     "14: post csr4 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     AppleCSR,
			response: "4",
			status:   http.StatusCreated,
		},
		{
			desc:     "15: get csr4 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/4",
			data:     "",
			response: expectedGetCertReqResponseBody2,
			status:   http.StatusOK,
		},
		{
			desc:     "16: post cert2 fail 1",
			method:   "POST",
			path:     "/api/v1/certificate_requests/4/certificate",
			data:     BananaCert,
			response: "error: cert validation failed: less than 2 certificate PEM strings were found",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "17: post cert2 fail 2",
			method:   "POST",
			path:     "/api/v1/certificate_requests/4/certificate",
			data:     "some random data that's clearly not a cert",
			response: "error: cert validation failed: less than 2 certificate PEM strings were found",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "18: post cert2 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests/2/certificate",
			data:     fmt.Sprintf("%s\n%s", BananaCert, IssuerCert),
			response: "1",
			status:   http.StatusCreated,
		},
		{
			desc:     "19: get csr2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/2",
			data:     "",
			response: expectedGetCertReqResponseBody3,
			status:   http.StatusOK,
		},
		{
			desc:     "20: reject csr4 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests/4/certificate/reject",
			data:     "",
			response: "1",
			status:   http.StatusAccepted,
		},
		{
			desc:     "21: get all csrs success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody3,
			status:   http.StatusOK,
		},
		{
			desc:     "22: delete csr2 cert success",
			method:   "DELETE",
			path:     "/api/v1/certificate_requests/2/certificate",
			data:     "",
			response: "1",
			status:   http.StatusAccepted,
		},
		{
			desc:     "23: get csr2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/2",
			data:     "",
			response: expectedGetCertReqResponseBody4,
			status:   http.StatusOK,
		},
		{
			desc:     "24: get csrs 3 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody4,
			status:   http.StatusOK,
		},
		{
			desc:     "25: healthcheck success",
			method:   "GET",
			path:     "/status",
			data:     "",
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "26: metrics endpoint success",
			method:   "GET",
			path:     "/metrics",
			data:     "",
			response: "",
			status:   http.StatusOK,
		},
	}
	for _, tC := range testCases {
		t.Run(fmt.Sprintf("step %s", tC.desc), func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
			req.Header.Set("Authorization", "Bearer "+adminToken)
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
		})
	}

}

func TestNotaryUsersHandlers(t *testing.T) {
	testdb, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	ts := httptest.NewTLSServer(server.NewNotaryRouter(env))
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
			response: "error: forbidden",
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
			response: "error: id not found",
			status:   http.StatusNotFound,
		},
		{
			desc:     "Create user failure",
			method:   "POST",
			path:     "/api/v1/accounts",
			data:     invalidUser,
			auth:     adminToken,
			response: "error: Username is required",
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
			response: "id not found",
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
			response: "error: id not found",
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

func TestLogin(t *testing.T) {
	testdb, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	env.JWTSecret = []byte("secret")
	ts := httptest.NewTLSServer(server.NewNotaryRouter(env))
	defer ts.Close()

	client := ts.Client()

	testCases := []struct {
		desc     string
		method   string
		path     string
		data     string
		response string
		status   int
	}{
		{
			desc:     "Create admin user",
			method:   "POST",
			path:     "/api/v1/accounts",
			data:     adminUser,
			response: "{\"id\":1}",
			status:   http.StatusCreated,
		},
		{
			desc:     "Login success",
			method:   "POST",
			path:     "/login",
			data:     adminUser,
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "Login failure missing username",
			method:   "POST",
			path:     "/login",
			data:     invalidUser,
			response: "Username is required",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Login failure missing password",
			method:   "POST",
			path:     "/login",
			data:     noPasswordUser,
			response: "Password is required",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "Login failure invalid password",
			method:   "POST",
			path:     "/login",
			data:     adminUserWrongPass,
			response: "error: The username or password is incorrect. Try again.",
			status:   http.StatusUnauthorized,
		},
		{
			desc:     "Login failure invalid username",
			method:   "POST",
			path:     "/login",
			data:     notExistingUser,
			response: "error: The username or password is incorrect. Try again.",
			status:   http.StatusUnauthorized,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			req, err := http.NewRequest(tC.method, ts.URL+tC.path, strings.NewReader(tC.data))
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
			if tC.desc == "Login success" && res.StatusCode == http.StatusOK {
				token, parseErr := jwt.Parse(string(resBody), func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(env.JWTSecret), nil
				})
				if parseErr != nil {
					t.Errorf("Error parsing JWT: %v", parseErr)
					return
				}

				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					if claims["username"] != "testadmin" {
						t.Errorf("Username found in JWT does not match expected value.")
					} else if int(claims["permissions"].(float64)) != 1 {
						t.Errorf("Permissions found in JWT does not match expected value.")
					}
				} else {
					t.Errorf("Invalid JWT token or JWT claims are not readable")
				}
			}
		})
	}
}

func TestAuthorization(t *testing.T) {
	testdb, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	env.JWTSecret = []byte("secret")
	ts := httptest.NewTLSServer(server.NewNotaryRouter(env))
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
			response: "error: deleting an Admin account is not allowed.",
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

func prepareUserAccounts(url string, client *http.Client, adminToken, nonAdminToken *string) func(*testing.T) {
	return func(t *testing.T) {
		req, err := http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(adminUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("creating the first request should succeed when unauthorized. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(validUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the second request should have been rejected. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/login", strings.NewReader(adminUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resBody, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("the admin login request should have succeeded. status code received: %d", res.StatusCode)
		}
		*adminToken = string(resBody)
		req, err = http.NewRequest("POST", url+"/api/v1/accounts", strings.NewReader(validUser))
		req.Header.Set("Authorization", "Bearer "+*adminToken)
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("creating the second request should have succeeded when given the admin auth header. status code received: %d", res.StatusCode)
		}
		req, err = http.NewRequest("POST", url+"/login", strings.NewReader(validUser))
		if err != nil {
			t.Fatal(err)
		}
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resBody, err = io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Errorf("the admin login request should have succeeded. status code received: %d", res.StatusCode)
		}
		*nonAdminToken = string(resBody)
	}
}

// trimmed removes all whitespace and newlines from a given string
func trimmed(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\\n")
}
