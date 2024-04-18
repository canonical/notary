package server_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	server "github.com/canonical/gocert/internal/api"
	"github.com/canonical/gocert/internal/certdb"
)

const (
	validCSR1 = `-----BEGIN CERTIFICATE REQUEST-----
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
-----END CERTIFICATE REQUEST-----`
	validCSR2 = `-----BEGIN CERTIFICATE REQUEST-----
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
	validCSR3 = `-----BEGIN CERTIFICATE REQUEST-----
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
-----END CERTIFICATE REQUEST-----`
	validCert2 = `-----BEGIN CERTIFICATE-----
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
)

const (
	expectedGetAllCertsResponseBody1 = "[{\"ID\":1,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\\nDQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn\\noJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+\\nL0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg\\nFzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR\\n+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC\\n+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq\\nhkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD\\nAQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL\\nBQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60\\ncuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5\\nzHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2\\nY/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID\\nuMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS\\ny+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"}]"
	expectedGetAllCertsResponseBody2 = "[{\"ID\":1,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\\nDQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn\\noJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+\\nL0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg\\nFzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR\\n+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC\\n+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq\\nhkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD\\nAQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL\\nBQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60\\ncuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5\\nzHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2\\nY/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID\\nuMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS\\ny+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"},{\"ID\":2,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk\\nMzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG\\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi\\npUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI\\n69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW\\nXcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO\\nyae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW\\nKl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ\\nKoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs\\ndC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3\\nDQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V\\nFGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa\\nuHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87\\ncAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+\\nRSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1\\nH9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"}]"
	expectedGetAllCertsResponseBody3 = "[{\"ID\":2,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk\\nMzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG\\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi\\npUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI\\n69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW\\nXcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO\\nyae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW\\nKl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ\\nKoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs\\ndC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3\\nDQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V\\nFGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa\\nuHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87\\ncAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+\\nRSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1\\nH9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"-----BEGIN CERTIFICATE-----\\nMIIDrDCCApSgAwIBAgIURKr+jf7hj60SyAryIeN++9wDdtkwDQYJKoZIhvcNAQEL\\nBQAwOTELMAkGA1UEBhMCVVMxKjAoBgNVBAMMIXNlbGYtc2lnbmVkLWNlcnRpZmlj\\nYXRlcy1vcGVyYXRvcjAeFw0yNDAzMjcxMjQ4MDRaFw0yNTAzMjcxMjQ4MDRaMEcx\\nFjAUBgNVBAMMDTEwLjE1Mi4xODMuNTMxLTArBgNVBC0MJDM5YWNlMTk1LWRjNWEt\\nNDMyYi04MDkwLWFmZTZhYjRiNDljZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\\nAQoCggEBAIzOVs/h0bQ73kc3g5BAzOKK5yGnn3vHfJ5hYqVGrfaglN1Pe/fBUeOt\\nAx4wixsRccZqEYrcx7WkeHsOR9N+h5RgdtMmrPwjA4ElCOvQ8gLMj8BCajlgRjtS\\ny+dKl3Zef4zpDtr6APY+VLA9QrVkpJcoWzYVjKWKo9jm1l3GmI/Rsf08GIcPMbCf\\n0EVsgq7441cx/PuH63w4QVTsssDe7KviN1sAm8gQXDfLjsmntG/6uflCVIqoKXjg\\nIf+GO6iN2GqzI+HJu3cJoglY3nVMIeuc1ch7UFHy3fJxVipfe++ZjQXNconLyg1N\\n2QeYWdTGbaWzAcGgNcjEhK7P34eSml8CAwEAAaOBnTCBmjAhBgNVHSMEGjAYgBYE\\nFN/vgl9cAapV7hH9lEyM7qYS958aMB0GA1UdDgQWBBRJJDZkHr64VqTC24DPQVld\\nBa3iPDAMBgNVHRMBAf8EAjAAMEgGA1UdEQRBMD+CN3ZhdWx0LWs4cy0wLnZhdWx0\\nLWs4cy1lbmRwb2ludHMudmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBAqYtzUwDQYJ\\nKoZIhvcNAQELBQADggEBAEH9NTwDiSsoQt/QXkWPMBrB830K0dlwKl5WBNgVxFP+\\nhSfQ86xN77jNSp2VxOksgzF9J9u/ubAXvSFsou4xdP8MevBXoFJXeqMERq5RW3gc\\nWyhXkzguv3dwH+n43GJFP6MQ+n9W/nPZCUQ0Iy7ueAvj0HFhGyZzAE2wxNFZdvCs\\ngCX3nqYpp70oZIFDrhmYwE5ij5KXlHD4/1IOfNUKCDmQDgGPLI1tVtwQLjeRq7Hg\\nXVelpl/LXTQawmJyvDaVT/Q9P+WqoDiMjrqF6Sy7DzNeeccWVqvqX5TVS6Ky56iS\\nMvo/+PAJHkBciR5Xn+Wg2a+7vrZvT6CBoRSOTozlLSM=\\n-----END CERTIFICATE-----\"},{\"ID\":3,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\\nDQEBAQUAA4IBDwAwggEKAoIBAQDN7tHggWTtxiT5Sh5Npoif8J2BdpJjtMdpZ7Vu\\nNVzMxW/eojSRlq0p3nafmpjnSdSH1k/XMmPsgmv9txxEHMw1LIUJUef2QVrQTI6J\\n4ueu9NvexZWXZ+UxFip63PKyn/CkZRFiHCRIGzDDPxM2aApjghXy9ISMtGqDVSnr\\n5hQDu2U1CEiUWKMoTpyk/KlBZliDDOzaGm3cQuzKWs6Stjzpq+uX4ecJAXZg5Cj+\\n+JUETH93A/VOfsiiHXoKeTnFMCsmJgEHz2DZixw8EN8XgpOp5BA2n8Y/xS+Ren5R\\nZH7uNJI/SmQ0yrR+2bYR6hm+4bCzspyCfzbiuI5IS9+2eXA/AgMBAAGgWDBWBgkq\\nhkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD\\nAQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL\\nBQADggEBAB/aPfYLbnCubYyKnxLRipoLr3TBSYFnRfcxiZR1o+L3/tuv2NlrXJjY\\nK13xzzPhwuZwd6iKfX3xC33sKgnUNFawyE8IuAmyhJ2cl97iA2lwoYcyuWP9TOEx\\nLT60zxp7PHsKo53gqaqRJ5B9RZtiv1jYdUZvynHP4J5JG7Zwaa0VNi/Cx5cwGW8K\\nrfvNABPUAU6xIqqYgd2heDPF6kjvpoNiOl056qIAbk0dbmpqOJf/lxKBRfqlHhSC\\n0qRScGu70l2Oxl89YSsfGtUyQuzTkLshI2VkEUM+W/ZauXbxLd8SyWveH3/7mDC+\\nSgi7T+lz+c1Tw+XFgkqryUwMeG2wxt8=\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"},{\"ID\":4,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\\nDQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn\\noJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+\\nL0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg\\nFzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR\\n+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC\\n+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq\\nhkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD\\nAQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL\\nBQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60\\ncuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5\\nzHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2\\nY/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID\\nuMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS\\ny+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"}]"
	expectedGetCertReqResponseBody1  = "{\"ID\":2,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk\\nMzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG\\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi\\npUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI\\n69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW\\nXcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO\\nyae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW\\nKl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ\\nKoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs\\ndC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3\\nDQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V\\nFGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa\\nuHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87\\ncAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+\\nRSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1\\nH9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"}"
	expectedGetCertReqResponseBody2  = "{\"ID\":4,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIICszCCAZsCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3\\nDQEBAQUAA4IBDwAwggEKAoIBAQDC5KgrADpuOUPwSh0YLmpWF66VTcciIGC2HcGn\\noJknL7pm5q9qhfWGIdvKKlIA6cBB32jPd0QcYDsx7+AvzEvBuO7mq7v2Q1sPU4Q+\\nL0s2pLJges6/cnDWvk/p5eBjDLOqHhUNzpMUga9SgIod8yymTZm3eqQvt1ABdwTg\\nFzBs5QdSm2Ny1fEbbcRE+Rv5rqXyJb2isXSujzSuS22VqslDIyqnY5WaLg+pjZyR\\n+0j13ecJsdh6/MJMUZWheimV2Yv7SFtxzFwbzBMO9YFS098sy4F896eBHLNe9cUC\\n+d1JDtLaewlMogjHBHAxmP54dhe6vvc78anElKKP4hm5N5nlAgMBAAGgWDBWBgkq\\nhkiG9w0BCQ4xSTBHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD\\nAQYIKwYBBQUHAwIwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEL\\nBQADggEBACP1VKEGVYKoVLMDJS+EZ0CPwIYWsO4xBXgK6atHe8WIChVn/8I7eo60\\ncuMDiy4LR70G++xL1tpmYGRbx21r9d/shL2ehp9VdClX06qxlcGxiC/F8eThRuS5\\nzHcdNqSVyMoLJ0c7yWHJahN5u2bn1Lov34yOEqGGpWCGF/gT1nEvM+p/v30s89f2\\nY/uPl4g3jpGqLCKTASWJDGnZLroLICOzYTVs5P3oj+VueSUwYhGK5tBnS2x5FHID\\nuMNMgwl0fxGMQZjrlXyCBhXBm1k6PmwcJGJF5LQ31c+5aTTMFU7SyZhlymctB8mS\\ny+ErBQsRpcQho6Ok+HTXQQUcx7WNcwI=\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"\"}"
	expectedGetCertReqResponseBody3  = "{\"ID\":2,\"CSR\":\"-----BEGIN CERTIFICATE REQUEST-----\\nMIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk\\nMzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG\\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi\\npUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI\\n69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW\\nXcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO\\nyae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW\\nKl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ\\nKoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs\\ndC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3\\nDQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V\\nFGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa\\nuHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87\\ncAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+\\nRSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1\\nH9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI\\n-----END CERTIFICATE REQUEST-----\",\"Certificate\":\"-----BEGIN CERTIFICATE-----\\nMIIDrDCCApSgAwIBAgIURKr+jf7hj60SyAryIeN++9wDdtkwDQYJKoZIhvcNAQEL\\nBQAwOTELMAkGA1UEBhMCVVMxKjAoBgNVBAMMIXNlbGYtc2lnbmVkLWNlcnRpZmlj\\nYXRlcy1vcGVyYXRvcjAeFw0yNDAzMjcxMjQ4MDRaFw0yNTAzMjcxMjQ4MDRaMEcx\\nFjAUBgNVBAMMDTEwLjE1Mi4xODMuNTMxLTArBgNVBC0MJDM5YWNlMTk1LWRjNWEt\\nNDMyYi04MDkwLWFmZTZhYjRiNDljZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\\nAQoCggEBAIzOVs/h0bQ73kc3g5BAzOKK5yGnn3vHfJ5hYqVGrfaglN1Pe/fBUeOt\\nAx4wixsRccZqEYrcx7WkeHsOR9N+h5RgdtMmrPwjA4ElCOvQ8gLMj8BCajlgRjtS\\ny+dKl3Zef4zpDtr6APY+VLA9QrVkpJcoWzYVjKWKo9jm1l3GmI/Rsf08GIcPMbCf\\n0EVsgq7441cx/PuH63w4QVTsssDe7KviN1sAm8gQXDfLjsmntG/6uflCVIqoKXjg\\nIf+GO6iN2GqzI+HJu3cJoglY3nVMIeuc1ch7UFHy3fJxVipfe++ZjQXNconLyg1N\\n2QeYWdTGbaWzAcGgNcjEhK7P34eSml8CAwEAAaOBnTCBmjAhBgNVHSMEGjAYgBYE\\nFN/vgl9cAapV7hH9lEyM7qYS958aMB0GA1UdDgQWBBRJJDZkHr64VqTC24DPQVld\\nBa3iPDAMBgNVHRMBAf8EAjAAMEgGA1UdEQRBMD+CN3ZhdWx0LWs4cy0wLnZhdWx0\\nLWs4cy1lbmRwb2ludHMudmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBAqYtzUwDQYJ\\nKoZIhvcNAQELBQADggEBAEH9NTwDiSsoQt/QXkWPMBrB830K0dlwKl5WBNgVxFP+\\nhSfQ86xN77jNSp2VxOksgzF9J9u/ubAXvSFsou4xdP8MevBXoFJXeqMERq5RW3gc\\nWyhXkzguv3dwH+n43GJFP6MQ+n9W/nPZCUQ0Iy7ueAvj0HFhGyZzAE2wxNFZdvCs\\ngCX3nqYpp70oZIFDrhmYwE5ij5KXlHD4/1IOfNUKCDmQDgGPLI1tVtwQLjeRq7Hg\\nXVelpl/LXTQawmJyvDaVT/Q9P+WqoDiMjrqF6Sy7DzNeeccWVqvqX5TVS6Ky56iS\\nMvo/+PAJHkBciR5Xn+Wg2a+7vrZvT6CBoRSOTozlLSM=\\n-----END CERTIFICATE-----\"}"
)

func TestGoCertRouter(t *testing.T) {
	testdb, err := certdb.NewCertificateRequestsRepository(":memory:", "CertificateRequests")
	if err != nil {
		log.Fatalf("couldn't create test sqlite db: %s", err)
	}
	env := &server.Environment{}
	env.DB = testdb
	ts := httptest.NewTLSServer(server.NewGoCertRouter(env))
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
			desc:     "healthcheck success",
			method:   "GET",
			path:     "/status",
			data:     "",
			response: "",
			status:   http.StatusOK,
		},
		{
			desc:     "empty get csrs success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: "null",
			status:   http.StatusOK,
		},
		{
			desc:     "post csr1 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     validCSR1,
			response: "1",
			status:   http.StatusCreated,
		},
		{
			desc:     "get csrs 1 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody1,
			status:   http.StatusOK,
		},
		{
			desc:     "post csr2 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     validCSR2,
			response: "2",
			status:   http.StatusCreated,
		},
		{
			desc:     "get csrs 2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody2,
			status:   http.StatusOK,
		},
		{
			desc:     "post csr2 fail",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     validCSR2,
			response: "error: given csr already recorded",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "post csr3 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     validCSR3,
			response: "3",
			status:   http.StatusCreated,
		},
		{
			desc:     "delete csr1 success",
			method:   "DELETE",
			path:     "/api/v1/certificate_requests/1",
			data:     "",
			response: "",
			status:   http.StatusNoContent,
		},
		{
			desc:     "get csr1 fail",
			method:   "GET",
			path:     "/api/v1/certificate_requests/1",
			data:     "",
			response: "error: csr id not found",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "get csr2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/2",
			data:     "",
			response: expectedGetCertReqResponseBody1,
			status:   http.StatusOK,
		},
		{
			desc:     "post csr4 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests",
			data:     validCSR1,
			response: "4",
			status:   http.StatusCreated,
		},
		{
			desc:     "get csr4 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/4",
			data:     "",
			response: expectedGetCertReqResponseBody2,
			status:   http.StatusOK,
		},
		{
			desc:     "post cert2 fail",
			method:   "POST",
			path:     "/api/v1/certificate_requests/4/certificate",
			data:     validCert2,
			response: "error: certificate does not match CSR",
			status:   http.StatusBadRequest,
		},
		{
			desc:     "post cert2 success",
			method:   "POST",
			path:     "/api/v1/certificate_requests/2/certificate",
			data:     validCert2,
			response: "4",
			status:   http.StatusCreated,
		},
		{
			desc:     "get csr2 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests/2",
			data:     "",
			response: expectedGetCertReqResponseBody3,
			status:   http.StatusOK,
		},
		{
			desc:     "get csrs 3 success",
			method:   "GET",
			path:     "/api/v1/certificate_requests",
			data:     "",
			response: expectedGetAllCertsResponseBody3,
			status:   http.StatusOK,
		},
		{
			desc:     "healthcheck success",
			method:   "GET",
			path:     "/status",
			data:     "",
			response: "",
			status:   http.StatusOK,
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
			if res.StatusCode != tC.status || string(resBody) != tC.response {
				t.Errorf("expected response did not match.\nExpected vs Received status code: %d vs %d\nExpected vs Received body: \n%s\nvs\n%s\n", tC.status, res.StatusCode, tC.response, string(resBody))
			}
		})
	}

}
