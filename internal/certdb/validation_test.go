package certdb_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/canonical/gocert/internal/certdb"
)

var ValidCSR1 string = `-----BEGIN CERTIFICATE REQUEST-----
MIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn
oJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+
L0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg
FzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR
+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC
+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq
hkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL
BQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60
cuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5
zHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2
Y/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID
uMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS
y+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=
-----END CERTIFICATE REQUEST-----
`
var ValidCSR2 string = `-----BEGIN CERTIFICATE REQUEST-----
MIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk
MzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi
pUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI
69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW
XcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO
yae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW
Kl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ
KoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs
dC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3
DQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V
FGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa
uHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87
cAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+
RSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1
H9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI
-----END CERTIFICATE REQUEST-----`

var ValidCSR3 string = `-----BEGIN CERTIFICATE REQUEST-----
MIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDN7tHggWTtxiT5Sh5Npoif8J2BdpJjtMdpZ7Vu
NVzMxW/eojSRlq0p3nafmpjnSdSH1k/XMmPsgmv9txxEHMw1LIUJUef2QVrQTI6J
4ueu9NvexZWXZ+UxFip63PKyn/CkZRFiHCRIGzDDPxM2aApjghXy9ISMtGqDVSnr
5hQDu2U1CEiUWKMoTpyk/KlBZliDDOzaGm3cQuzKWs6Stjzpq+uX4ecJAXZg5Cj+
+JUETH93A/VOfsiiHXoKeTnFMCsmJgEHz2DZixw8EN8XgpOp5BA2n8Y/xS+Ren5R
ZH7uNJI/SmQ0yrR+2bYR6hm+4bCzspyCfzbiuI5IS9+2eXA/AgMBAAGgWDBWBgkq
hkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL
BQADggEBAB/aPfYLbnCubYyKnxLRipoLr3TBSYFnRfcxiZR1o+L3/tuv2NlrXJjY
K13xzzPhwuZwd6iKfX3xC33sKgnUNFawyE8IuAmyhJ2cl97iA2lwoYcyuWP9TOEx
LT60zxp7PHsKo53gqaqRJ5B9RZtiv1jYdUZvynHP4J5JG7Zwaa0VNi/Cx5cwGW8K
rfvNABPUAU6xIqqYgd2heDPF6kjvpoNiOl056qIAbk0dbmpqOJf/lxKBRfqlHhSC
0qRScGu70l2Oxl89YSsfGtUyQuzTkLshI2VkEUM+W/ZauXbxLd8SyWveH3/7mDC+
Sgi7T+lz+c1Tw+XFgkqryUwMeG2wxt8=
-----END CERTIFICATE REQUEST-----
`

var ValidCert2 string = `-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIURKr+jf7hj60SyAryIeN++9wDdtkwDQYJKoZIhvcNAQEL
BQAwOTELMAkGA1UEBhMCVVMxKjAoBgNVBAMMIXNlbGYtc2lnbmVkLWNlcnRpZmlj
YXRlcy1vcGVyYXRvcjAeFw0yNDAzMjcxMjQ4MDRaFw0yNTAzMjcxMjQ4MDRaMEcx
FjAUBgNVBAMMDTEwLjE1Mi4xODMuNTMxLTArBgNVBC0MJDM5YWNlMTk1LWRjNWEt
NDMyYi04MDkwLWFmZTZhYjRiNDljZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAIzOVs/h0bQ73kc3g5BAzOKK5yGnn3vHfJ5hYqVGrfaglN1Pe/fBUeOt
Ax4wixsRccZqEYrcx7WkeHsOR9N+h5RgdtMmrPwjA4ElCOvQ8gLMj8BCajlgRjtS
y+dKl3Zef4zpDtr6APY+VLA9QrVkpJcoWzYVjKWKo9jm1l3GmI/Rsf08GIcPMbCf
0EVsgq7441cx/PuH63w4QVTsssDe7KviN1sAm8gQXDfLjsmntG/6uflCVIqoKXjg
If+GO6iN2GqzI+HJu3cJoglY3nVMIeuc1ch7UFHy3fJxVipfe++ZjQXNconLyg1N
2QeYWdTGbaWzAcGgNcjEhK7P34eSml8CAwEAAaOBnTCBmjAhBgNVHSMEGjAYgBYE
FN/vgl9cAapV7hH9lEyM7qYS958aMB0GA1UdDgQWBBRJJDZkHr64VqTC24DPQVld
Ba3iPDAMBgNVHRMBAf8EAjAAMEgGA1UdEQRBMD+CN3ZhdWx0LWs4cy0wLnZhdWx0
LWs4cy1lbmRwb2ludHMudmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBAqYtzUwDQYJ
KoZIhvcNAQELBQADggEBAEH9NTwDiSsoQt/QXkWPMBrB830K0dlwKl5WBNgVxFP+
hSfQ86xN77jNSp2VxOksgzF9J9u/ubAXvSFsou4xdP8MevBXoFJXeqMERq5RW3gc
WyhXkzguv3dwH+n43GJFP6MQ+n9W/nPZCUQ0Iy7ueAvj0HFhGyZzAE2wxNFZdvCs
gCX3nqYpp70oZIFDrhmYwE5ij5KXlHD4/1IOfNUKCDmQDgGPLI1tVtwQLjeRq7Hg
XVelpl/LXTQawmJyvDaVT/Q9P+WqoDiMjrqF6Sy7DzNeeccWVqvqX5TVS6Ky56iS
Mvo/+PAJHkBciR5Xn+Wg2a+7vrZvT6CBoRSOTozlLSM=
-----END CERTIFICATE-----`

func TestCSRValidationSuccess(t *testing.T) {
	cases := []string{ValidCSR1, ValidCSR2, ValidCSR3}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCSR%d", i), func(t *testing.T) {
			if err := certdb.ValidateCertificateRequest(c); err != nil {
				t.Errorf("Couldn't verify valid CSR: %s", err)
			}
		})
	}
}

func TestCSRValidationFail(t *testing.T) {
	var wrongString = "this is a real csr!!!"
	var wrongStringErr = "PEM Certificate Request string not found or malformed"
	var ValidCSRWithoutWhitespace = strings.ReplaceAll(ValidCSR1, "\n", "")
	var ValidCSRWithoutWhitespaceErr = "PEM Certificate Request string not found or malformed"
	var wrongPemType = strings.ReplaceAll(ValidCSR1, "CERTIFICATE REQUEST", "SOME RANDOM PEM TYPE")
	var wrongPemTypeErr = "given PEM string not a certificate request"
	var InvalidCSR = strings.ReplaceAll(ValidCSR1, "/", "p")
	var InvalidCSRErr = "asn1: syntax error: invalid boolean"

	cases := []struct {
		input       string
		expectedErr string
	}{
		{
			input:       wrongString,
			expectedErr: wrongStringErr,
		},
		{
			input:       ValidCSRWithoutWhitespace,
			expectedErr: ValidCSRWithoutWhitespaceErr,
		},
		{
			input:       wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
		{
			input:       InvalidCSR,
			expectedErr: InvalidCSRErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCSR%d", i), func(t *testing.T) {
			err := certdb.ValidateCertificateRequest(c.input)
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestCertValidationSuccess(t *testing.T) {
	cases := []string{ValidCert2}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCert%d", i), func(t *testing.T) {
			if err := certdb.ValidateCertificate(c, ValidCSR2); err != nil {
				t.Errorf("Couldn't verify valid Cert: %s", err)
			}
		})
	}
}

func TestCertValidationFail(t *testing.T) {
	var wrongCertString = "this is a real cert!!!"
	var wrongCertStringErr = "PEM Certificate string not found or malformed"
	var ValidCertWithoutWhitespace = strings.ReplaceAll(ValidCert2, "\n", "")
	var ValidCertWithoutWhitespaceErr = "PEM Certificate string not found or malformed"
	var wrongPemType = strings.ReplaceAll(ValidCert2, "CERTIFICATE", "SOME RANDOM PEM TYPE")
	var wrongPemTypeErr = "given PEM string not a certificate"
	var InvalidCert = strings.ReplaceAll(ValidCert2, "M", "i")
	var InvalidCertErr = "x509: malformed certificate"
	var certificateDoesNotMatchErr = "certificate does not match CSR"

	cases := []struct {
		inputCSR    string
		inputCert   string
		expectedErr string
	}{
		{
			inputCSR:    ValidCSR2,
			inputCert:   wrongCertString,
			expectedErr: wrongCertStringErr,
		},
		{
			inputCSR:    ValidCSR2,
			inputCert:   ValidCertWithoutWhitespace,
			expectedErr: ValidCertWithoutWhitespaceErr,
		},
		{
			inputCSR:    ValidCSR2,
			inputCert:   wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
		{
			inputCSR:    ValidCSR2,
			inputCert:   InvalidCert,
			expectedErr: InvalidCertErr,
		},
		{
			inputCSR:    ValidCSR1,
			inputCert:   ValidCert2,
			expectedErr: certificateDoesNotMatchErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := certdb.ValidateCertificate(c.inputCert, c.inputCSR)
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\n Expected: %s", err, c.expectedErr)
			}
		})
	}
}
