package db_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
)

const (
	RootCACSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIDIzCCAgsCAQAwcjELMAkGA1UEBhMCVFIxDjAMBgNVBAgTBUl6bWlyMRIwEAYD
VQQHEwlOYXJsaWRlcmUxEjAQBgNVBAoTCUNhbm9uaWNhbDERMA8GA1UECxMISWRl
bnRpdHkxGDAWBgNVBAMTD1Rlc3RpbmcgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAJ4jlVsv7QmEW5rYZxj0ZKO5Ck+qzrW3m2S08xPrvP+b
H7qwjhYZr7psi7BW8bRDOv1QHZNYojr28eyThikf1xi/lNsSFJdJxd3BO8scukcZ
KmmkQEw97BdOwLZNdHaowKshO9IrwDukB49w75amImHF6jcz0pqS1d/6vo53btE7
5mnlm/dy3rAVLh05Ty9Gi//L1cpCDVaMXed/p2quNQ3OaygO6r2vtVSODMng5AN/
vbniXTimG78PtPEwvLkPa5Wlznm0WjVP4/9RLRyym5rTVbDb+T80G9JDlq3f1Dc9
I+/0+o3PDFQRTFV6pkg8h2cqucX5Aq8G4QxrUPt1PJECAwEAAaBsMBwGCSqGSIb3
DQEJAjEPEw1UZXN0aW5nUm9vdENBMEwGCSqGSIb3DQEJDjE/MD0wDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQUBd3se3z+TC8S6pvnWM3T7T9Ha6AwCwYDVR0PBAQD
AgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBkVycm15ao7GwooOyIAo0GPG11v/JIiWiZ
+UqtElxo3pIQ1zy2tgJlRWD8u1GzevWUOXovXCXqMY7oHtJMS7/fECRFDPvxXWIY
5a06njEeUqLLTJi8YQGNJ7bSR6rzdRxM2WOimAb0mCuNonKtLxPVUCQW8TBpY6i9
Nwnv5tcVAaN1Oy5FoEN99WVcc+ItgRMclLMdn23saZxosiBsMz9gvTP8PZeZmbcY
O2Z6FciAaCKs3+8dpIFRBWG8P02W5Ob+guEmfsq+kJdjx4Y7wwElGaydnVhZGbU/
mhNvhbg9Xh1KhemHRYRRisB/JGCaa1BSPh9sIypBWt3inxjvbnlj
-----END CERTIFICATE REQUEST-----
`
	RootCAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAniOVWy/tCYRbmthnGPRko7kKT6rOtbebZLTzE+u8/5sfurCO
FhmvumyLsFbxtEM6/VAdk1iiOvbx7JOGKR/XGL+U2xIUl0nF3cE7yxy6RxkqaaRA
TD3sF07Atk10dqjAqyE70ivAO6QHj3DvlqYiYcXqNzPSmpLV3/q+jndu0TvmaeWb
93LesBUuHTlPL0aL/8vVykINVoxd53+naq41Dc5rKA7qva+1VI4MyeDkA3+9ueJd
OKYbvw+08TC8uQ9rlaXOebRaNU/j/1EtHLKbmtNVsNv5PzQb0kOWrd/UNz0j7/T6
jc8MVBFMVXqmSDyHZyq5xfkCrwbhDGtQ+3U8kQIDAQABAoIBAADaYJPFSM7cxZp6
n+bp3xQwbecp/NtXYCWGpxrF96nB5Zr7WQndcGXrMC9MDxnYWhRWmxE8g2QEaTUh
WCzRvYEbpp8OUaQoXLKRIwxJ1XH88hOlBDKGa+cLM1rhujQ0vZ99XSIZfwayADcw
g5StRN6rMNPZ8gZyzofqtX363uh5UJYxbDNjb56TTCjHxTZStZaKbnCce7SmbZ9a
1MCPnMQ3KD/itxpIpSmpb8zu6AIPyIsG4T0ctGsP5CcXWkc7gStCH7+Y1MlrgYqj
v6I9ATranUJTu6FNQstPSrJ3TeiB3cWkJKSlh1FOOMsRZG4W/eDghG3JDnll7ZKf
1vFJAIECgYEA2y+zilFHooCkq5ze0eCknSFQFRcU5zSvoWLpoVTy3FJyWZUcVi7W
+aJ2Ok+jF9AmkTETOtioJl/PRa26CEawIWtgE9wjNxc0Qi0RNdvPfcmcL/KDGaok
aL887qiuxPfKISbOwx6R7ip5CaXwPIHj2zS9Ae5MMRfI0PwxOXeMjYECgYEAuLML
oWSI6mEDU3N5tWAwhJ2wSEPVpR98vaP78erNvblJqJKBYYWKN6YiDDtNZOmfIP64
KV2iXMqy49VQgqFjPQAioh8GhH/CzS319ywmE9tgMN/cFH68r3KccY2OUuVGi5kp
JgqYGWjiL/riHIuzvd4cc+5QrfWiC72teA2JVxECgYBtNPYii17Cs4/YRX+rWF8M
PwXUjDyI+fIr2cmH7XhXl+iLg8SrmAjaNjzrzrP28GnW23m2Ty5weDoggG95Iict
b39eRcdx8mjCNAwoJo3aIXJlXVI+nkwnuGjWjEsPrloSbHCGPRv+a0EFMp1guGLb
3An0BVQG/c+7eHvaIxtvgQKBgQCwJWGELEM/dAIeBlUem3vqHhFO+hK5BcyLd+cC
ErLgq+MJt59YiGkHJZP3Il9vTDcM2qB8IuaDpHTzQC8mRhBEzuo4v2oR117LG3gm
oJ439dJJClXz3eLJWH7G9P+1IyAiZpGNzDC+mv6MT7JxEvL6sudj0PZ00XwXwm+7
vP0sYQKBgQCG70DYGJaboUavfywNBVqkh9/6TTvURM6F0cszjSXUfAqWA18VXA3d
m06g0yBoeDCgZUtdd5Y7GtCX2/tcKR7pZK8tO5rDccnpi0qn/1Z0qNXoUuk9VyFs
MUksCY/7cVN4D5j0KDDI1OlYoKWDshk+QqLPPRNnlicXPSJGyziKaA==
-----END RSA PRIVATE KEY-----
`
	RootCACertificate = `-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIIePW5BN4IJmIwDQYJKoZIhvcNAQELBQAwcjELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMRIwEAYDVQQHEwlOYXJsaWRlcmUxEjAQBgNV
BAoTCUNhbm9uaWNhbDERMA8GA1UECxMISWRlbnRpdHkxGDAWBgNVBAMTD1Rlc3Rp
bmcgUm9vdCBDQTAeFw0yNTAyMjQwMDAwMDBaFw0zNTAyMjMyMzU5NTlaMHIxCzAJ
BgNVBAYTAlRSMQ4wDAYDVQQIEwVJem1pcjESMBAGA1UEBxMJTmFybGlkZXJlMRIw
EAYDVQQKEwlDYW5vbmljYWwxETAPBgNVBAsTCElkZW50aXR5MRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCe
I5VbL+0JhFua2GcY9GSjuQpPqs61t5tktPMT67z/mx+6sI4WGa+6bIuwVvG0Qzr9
UB2TWKI69vHsk4YpH9cYv5TbEhSXScXdwTvLHLpHGSpppEBMPewXTsC2TXR2qMCr
ITvSK8A7pAePcO+WpiJhxeo3M9KaktXf+r6Od27RO+Zp5Zv3ct6wFS4dOU8vRov/
y9XKQg1WjF3nf6dqrjUNzmsoDuq9r7VUjgzJ4OQDf7254l04phu/D7TxMLy5D2uV
pc55tFo1T+P/US0cspua01Ww2/k/NBvSQ5at39Q3PSPv9PqNzwxUEUxVeqZIPIdn
KrnF+QKvBuEMa1D7dTyRAgMBAAGjQjBAMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
VR0OBBYEFAXd7Ht8/kwvEuqb51jN0+0/R2ugMAsGA1UdDwQEAwIBBjANBgkqhkiG
9w0BAQsFAAOCAQEAVBHIsi33AYnB1ffy7/sLoGPzRx033FtFJtG8Wg1u8MR99CnI
quOREWOoDSbupqVAE6b02IJjn+eDZbWpKFhYMQnDc7fInoNnLzvj5BulAKcGbz9L
14G92pC8dRojW2pLKOgWHyaOavdzwp7EMmnQq8GkK9fg0gkdZTuujwusBRpCKGf6
YtyL4MTaWv3/F/b+SyL/sjYWxTBSjmMscV2ZYSaWWi99jHB5zT8tgpILrUtwb9mt
FSMVFFeS89IfbO294ipP8UD/A9DpMTOCl1bTnfgSef9tJ5GOoXKeiW+Pr/NpVWJE
Vr1E5wQ9VYY3TJRfnqnxhckuNqW8ePnL6uyeCw==
-----END CERTIFICATE-----
`
	RootCACRL = `-----BEGIN X509 CRL-----
MIIB8zCB3AIBATANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJUUjEOMAwGA1UE
CBMFSXptaXIxEjAQBgNVBAcTCU5hcmxpZGVyZTESMBAGA1UEChMJQ2Fub25pY2Fs
MREwDwYDVQQLEwhJZGVudGl0eTEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBFw0y
NTAzMjUwMDUwNTVaFw0yNjAzMjUwMDUwNTVaoDYwNDAfBgNVHSMEGDAWgBQF3ex7
fP5MLxLqm+dYzdPtP0droDARBgNVHRQECgIIGC/lcS7/dH4wDQYJKoZIhvcNAQEL
BQADggEBAFLrH+1paVPKYr8cRAEBPtSRxp23YbbbcC40irmmYlHoOEooRAJ8+nw3
ZUX4A527Bjr+Pbu/9klXZhCAS4r8fFT3veJQ1mp/kEZOsBG9h0bCN4Jwpqix2f1W
6z3AcPiwg636KPaze8pwUcqSfQSwmfzwl3E8vkzD29dy6tXwKTdgaUP7uHrzeHDi
rtA9e9+8gbbad1I9lwdd2Q4qgt3mUIjwn5SV9sSEaSApT8i/Z72RHLpGJNl3JpO1
0599PMgFeP6VruT8IYhfj7iEY2lqiyWMXoXsgGwhD8PAqKcJ03vavUNrfhkT+Jl9
yxat/tt2TxlkcAxv4nrxhR208GXqpE0=
-----END X509 CRL-----
`
	IntermediateCACSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIDSDCCAjACAQAwgYMxCzAJBgNVBAYTAlRSMQ4wDAYDVQQIEwVJem1pcjESMBAG
A1UEBxMJTmFybGlkZXJlMRIwEAYDVQQKEwlDYW5vbmljYWwxETAPBgNVBAsTCElk
ZW50aXR5MSkwJwYDVQQDEyBUZXN0aW5nIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0
ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJeopnEd2pnzeLkx2LTs
R4XBSjNrOE2xKdikLg4jPX2xyxGDG38LbWFF/BxnqoQpLzJF2U5ky9Qcr/YwoJIY
ENXs3iuqVUOzWMPZvpnsUFjNmHPRqpXg5TtJz+t9U48cwuU+pdbJGzNikcsB9iX8
ifw5e0WA9KLAuzUkSKIkPsI9b52Wx/6XGJF4I8th/tCATiBn7pli5U9hC134E4X+
q2AyWClQ7ACGPlz/Co+R+LMnbS+VjpfIyXeETTcGaC8Xi0fUdTH+UVB08xLptOYW
1UdhBs13aPHVtNZD/rLIwSp/qhsWRrR2zj59Mgn7QItlvYaFr4VipXBXKxfXsy/L
8E8CAwEAAaB/MC8GCSqGSIb3DQEJAjEiEyBUZXN0aW5nIEludGVybWVkaWF0ZSBD
ZXJ0aWZpY2F0ZTBMBgkqhkiG9w0BCQ4xPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFESclAudy5VkKTbPyn8qaubux227MAsGA1UdDwQEAwIBBjANBgkqhkiG
9w0BAQsFAAOCAQEAFU0KWip09/9hML/gUzSegNMScwxWfvHqR09y8Vn03WX6ICEz
K8LUKgXq4L9Nbto1wvCMVtF8pV1rFUTbjCchNMvgqsd3efCstQfrZL6fYXSbWJ2g
EghxFd08coU1El6QBQhq+XVfR6diYikQZU89RaFfBLKv7EUJCDSFIo3v4aox/K0C
BRBeNKIQfsKtzaSutzNlF4v/rmoqjupetFpZ94OA+7x2bxdkrXbdRR595bGZgCpJ
hfIVT87GjLrXLmFHEI2tp5JqiohSRoxy13kL/8OdK2xNuzbKytkyZreRvviLYUgm
pLdZQu2qaOBwTBhefS5nXNHSpzm+U5I0TXKGSg==
-----END CERTIFICATE REQUEST-----
`
	IntermediateCAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAl6imcR3amfN4uTHYtOxHhcFKM2s4TbEp2KQuDiM9fbHLEYMb
fwttYUX8HGeqhCkvMkXZTmTL1Byv9jCgkhgQ1ezeK6pVQ7NYw9m+mexQWM2Yc9Gq
leDlO0nP631TjxzC5T6l1skbM2KRywH2JfyJ/Dl7RYD0osC7NSRIoiQ+wj1vnZbH
/pcYkXgjy2H+0IBOIGfumWLlT2ELXfgThf6rYDJYKVDsAIY+XP8Kj5H4sydtL5WO
l8jJd4RNNwZoLxeLR9R1Mf5RUHTzEum05hbVR2EGzXdo8dW01kP+ssjBKn+qGxZG
tHbOPn0yCftAi2W9hoWvhWKlcFcrF9ezL8vwTwIDAQABAoIBAAbn7GuPOlwzT/NP
vhH/0zWK7gTCytjccRuteKMDkmVaxyf54+XyA8RfsJGS9bSFJmIjXlHDDKl3UVq9
4rn0WmPoOg+1kG9mR2vK5D9T5i69CGARxpmCzBcNW+hZyyHKFssXAlJyOVWQ+5mW
ci21pVgbPmFIwRsRX3tig31ndoVXi96tl7YlX60UfOJ2uQFdwY2lZq8wo2DE7VYs
RCOq4U3ys8l7ZMVPZ+LGi8FOFiXJvx/2H+byp+LpW5NKeRDfCFmHQ0XKKUpUYnGc
Kh7ftwT0tEht+bSK+Xh6XhZjav7UGTMC+zuAg+9ohU8JjUawVfXNnA8Bke6Upv+U
xvJL69ECgYEA0HIBKWFLSbJz9uezsmH2R5/cQO7IrlLvHZ9aEn7gvAlYxoIreZnC
LXBMhIfKgrbBHnDlDqOWJJ12SJ+8jijIJQzx1MUxB8F2NVNBLyh//xZQWYNANcug
YxbcmPsf7Ydm2cnkmd1dboZlPXTdpg3HnvLOf9xCiCmohp108SueJlECgYEAukIY
0NzEhw7nLxkfYR+Y2M5ErH3xNZZUUyFyW2EeNjowf2iLRkQhB1glPwHDIghz2fxn
0dOsPMQxk2fa9vJXFWjJSVfKebNKrY2uSv5cP3u6Xjiz1HGuZltNIj6wWeh4NbX/
matYl5zg7uYSXWbTBGSW4kQ8Bk7On7kNQ9DS5J8CgYEAypB/oH70c0IAf8jbUFby
xtgLau6iBwaBaQAawC6cpx9OLlsBdMJ/eTjQo1py6mQ/eB2t+3PtzNdYw2q4Ck6H
cboKqQKYizjubxPhHLr26CX/H331QFIKI0FsTx58AJC82pjglsYQrf/dEsQnQd/S
Rh0foBGkdj5Fj8wkgNoqboECgYEAkpVcJFvqSwQ+iwFxgaU1TEMhJsNDJtI1cOsc
ra/D8BdhfZPQMC+D8ty7C1gestUGH+MV7btxjK02+vQ8DibwxAegihkOXzLsLaQY
LCr8fHWqWWa0mBgTkbh+/tlpPojGujaOfuiroz4yg7ELePhoT8e+OzpKJwi0cl1X
hCx/HK8CgYAK7MSWLTbrIsWaXMWp36b0UYi/ooCx55fpUEiqa4pDppo+HWO3qIQ6
kTzhkDVM4UeTfI1vNFgkMyc7ZBTK0I3kXmx7yZLTh6q18YAPShi7JkAe8Pf2T+0g
Uvcl7qdfypv0ccF7BmPH70z/T8SZOgJZaLWak9twiTsGSMcfCqW4Kw==
-----END RSA PRIVATE KEY-----
`
	IntermediateCACertificate = `-----BEGIN CERTIFICATE-----
MIID2DCCAsCgAwIBAgIIJQ8HbMwoFyUwDQYJKoZIhvcNAQELBQAwcjELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMRIwEAYDVQQHEwlOYXJsaWRlcmUxEjAQBgNV
BAoTCUNhbm9uaWNhbDERMA8GA1UECxMISWRlbnRpdHkxGDAWBgNVBAMTD1Rlc3Rp
bmcgUm9vdCBDQTAeFw0yNTAyMjQwMDAwMDBaFw0zNTAyMjMyMzU5NTlaMIGDMQsw
CQYDVQQGEwJUUjEOMAwGA1UECBMFSXptaXIxEjAQBgNVBAcTCU5hcmxpZGVyZTES
MBAGA1UEChMJQ2Fub25pY2FsMREwDwYDVQQLEwhJZGVudGl0eTEpMCcGA1UEAxMg
VGVzdGluZyBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCXqKZxHdqZ83i5Mdi07EeFwUozazhNsSnYpC4OIz19
scsRgxt/C21hRfwcZ6qEKS8yRdlOZMvUHK/2MKCSGBDV7N4rqlVDs1jD2b6Z7FBY
zZhz0aqV4OU7Sc/rfVOPHMLlPqXWyRszYpHLAfYl/In8OXtFgPSiwLs1JEiiJD7C
PW+dlsf+lxiReCPLYf7QgE4gZ+6ZYuVPYQtd+BOF/qtgMlgpUOwAhj5c/wqPkfiz
J20vlY6XyMl3hE03BmgvF4tH1HUx/lFQdPMS6bTmFtVHYQbNd2jx1bTWQ/6yyMEq
f6obFka0ds4+fTIJ+0CLZb2Gha+FYqVwVysX17Mvy/BPAgMBAAGjYDBeMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFESclAudy5VkKTbPyn8qaubux227MB8GA1Ud
IwQYMBaAFAXd7Ht8/kwvEuqb51jN0+0/R2ugMAsGA1UdDwQEAwIBBjANBgkqhkiG
9w0BAQsFAAOCAQEABR11FOG9TmAFEMNGu5XEztRTAcldnj03Y67B5jpfFe7NBOqy
ltiEOnmWHMtbytxQJjySJ6uUn9F3PEYATnTqwOOL4gTVwmyaY7jbL1gw1NL40p8s
GJMyqZY+6Uo9S6XZCNjbUV6G88dfCQhX/eCGLMSsECUKEUuha0pVWcYYZ9vXCC1u
0bDFN3DOZWVztHt8azFaPJHIaU2GB1O50DtRwLUiLDywxT+CXcKqbzLrNyXrBRET
C7MI8h70C2nSuECxBB5dQvX+cUZPAxTvdROWD2jytfwduqpFg06gUFuKjQo3pXgV
FEA+f5Axiq+6pfJeYRF4cb7ceNJ0f+fGfm7j0A==
-----END CERTIFICATE-----
`
	IntermediateCACRL = `-----BEGIN X509 CRL-----
MIICBTCB7gIBATANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVFIxDjAMBgNV
BAgTBUl6bWlyMRIwEAYDVQQHEwlOYXJsaWRlcmUxEjAQBgNVBAoTCUNhbm9uaWNh
bDERMA8GA1UECxMISWRlbnRpdHkxKTAnBgNVBAMTIFRlc3RpbmcgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlFw0yNTAzMjUwMDUwNTVaFw0yNjAzMjUwMDUwNTVaoDYw
NDAfBgNVHSMEGDAWgBREnJQLncuVZCk2z8p/Kmrm7sdtuzARBgNVHRQECgIIGC/l
cS897V0wDQYJKoZIhvcNAQELBQADggEBABAdQokdJ/Ji4kPJ7W7H97EOKg80OISB
TuY+ivizzY4b9bogrA5C7pbRMpVDDDGIiYThEHh43LxJb4lB/1GgtPSGonRRuoXG
ypkZpBVGVhXXs2C5WiIbn0swQ0bi4rfUjk1tLdPITkBMWR78SjOAqVaOQ97s5g38
2v04Z79xL0vABtpUrF55gvArdzo6oAIlLplbBFeajqxJE2qH8umnWLHYV7EVwI+4
geYi6/WRzkRvV/+PEO09Mz/cYyv64DaFrz86EvdQb10Xt4Cf805MOY2WlvxtlI9e
QVKXWaC6xJiv+IBj0fNbi7wh3BOO8qaqvXvCgRdQt4UMqnKTgm2br0M=
-----END X509 CRL-----
`
)

func TestRootCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(RootCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" || ca.CertificateChain == "" {
		t.Fatalf("Certificate authority is not active or missing certificate")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CALegacy)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != db.CALegacy {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to legacy")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CALegacy)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != db.CALegacy {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to Active")
	}
	caRow, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CA to not be in the database: %s", err)
	}
	_, err = database.GetCertificateRequest(db.ByCSRID(caRow.CSRID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected CSR to not be in the database: %s", err)
	}
	_, err = database.GetPrivateKey(db.ByPrivateKeyID(caRow.PrivateKeyID))
	if !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("Expected PrivateKey to not be in the database: %s", err)
	}
}

func TestIntermediateCertificateAuthorityEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 0 {
		t.Fatalf("CA found when no CA's should be available")
	}

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "")
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err = database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csr, _ := database.GetCertificateRequest(db.ByCSRPEM(IntermediateCACSR)) // nolint: errcheck
	ca, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "pending" || ca.CertificateChain != "" {
		t.Fatalf("Certificate authority is not pending or has a certificate")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), IntermediateCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityCSRPEM(csr.CSR))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" || ca.CertificateChain != IntermediateCACertificate+"\n"+RootCACertificate {
		t.Fatalf("Certificate authority is not active or has a certificate")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CALegacy)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "legacy" {
		t.Fatalf("Certificate authority status is not legacy")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to legacy")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(ca.CertificateAuthorityID), db.CAActive)
	if err != nil {
		t.Fatalf("Couldn't update certificate authority status: %s", err)
	}
	ca, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't retrieve certificate authority: %s", err)
	}
	if ca.Status != "active" {
		t.Fatalf("Certificate authority status is not active")
	}
	if ca.CertificateChain == "" {
		t.Fatalf("Certificate should not have been removed when updating status to Active")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityID(ca.CertificateAuthorityID))
	if err != nil {
		t.Fatalf("Couldn't delete certificate authority: %s", err)
	}
}

func TestCertificateAuthorityFails(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	_, err = database.CreateCertificateAuthority("", "", "", "")
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "", "", "")
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "nope", "", "")
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", RootCAPrivateKey, RootCACRL, "")
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("", RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "", RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority("nope", RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, "nope", RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}
	_, err = database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, "", RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to create certificate authority")
	}

	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(0))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}
	_, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(1000))
	if err == nil {
		t.Fatalf("Should have failed to get certificate authority")
	}

	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(0), RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(10), RootCACertificate+"\n"+RootCACertificate)
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(1), "")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityCertificate(db.ByCertificateAuthorityID(1), "no")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}

	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(0), "Legacy")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(10), "Legacy")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}
	err = database.UpdateCertificateAuthorityStatus(db.ByCertificateAuthorityID(1), "No")
	if err == nil {
		t.Fatalf("Should have failed to update certificate authority")
	}

	err = database.DeleteCertificateAuthority(db.ByCertificateAuthorityCSRPEM("nope"))
	if err == nil {
		t.Fatalf("Should have failed to delete certificate authority")
	}
}

func TestSelfSignedCertificateList(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}
	cas, err := database.ListCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if len(cas) != 1 {
		t.Fatalf("%d CA's found when only 1 should be available", len(cas))
	}

	csrs, err := database.ListCertificateRequestWithCertificates()
	if err != nil {
		t.Fatalf("Couldn't list certificates: %s", err)
	}
	if len(csrs) != 1 {
		t.Fatalf("%d certificates found when only 1 should be available", len(csrs))
	}
	if csrs[0].CertificateChain == "" {
		t.Fatalf("certificate should be available for CSR")
	}
}

func TestSigningCSRsFromSelfSignedCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	caID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(caID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign CSR: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
}

func TestSigningCSRsFromIntermediateCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, IntermediateCACRL, IntermediateCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(caID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain == "" {
		t.Fatalf("Signed certificate not found.")
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected signed certificate chain to be 3 certificates long.")
	}
}

func TestSigningCSRFromUnsignedIntermediateCertificate(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	caID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "")
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	if caID != 1 {
		t.Fatalf("Error creating certificate authority: expected CA id to be 1 but it was %d", caID)
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(caID), "example.com")
	if err == nil {
		t.Fatalf("Expected signing to fail: %s", err)
	}

	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if csr.CertificateChain != "" {
		t.Fatalf("Certificate should not have been signed.")
	}
}

func TestSigningIntermediateCAByRootCA(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	rootCAID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	intermediateCAID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "")
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}

	err = database.SignCertificateRequest(db.ByCSRPEM(IntermediateCACSR), db.ByCertificateAuthorityID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}

	cas, err := database.ListDenormalizedCertificateAuthorities()
	if err != nil {
		t.Fatalf("Couldn't list certificate authorities: %s", err)
	}
	if strings.Count(cas[0].CertificateChain, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("Expected root ca certificate chain to be 1 certificates long.")
	}
	if strings.Count(cas[1].CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected intermediate ca certificate chain to be 2 certificates long.")
	}

	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(intermediateCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 3 {
		t.Fatalf("Expected end certificate chain to be 3 certificates long.")
	}

	csrID, err = database.CreateCertificateRequest(StrawberryCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
}
func TestCertificateRevocationListsEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	database, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatalf("Couldn't complete NewDatabase: %s", err)
	}
	defer database.Close()

	// The root CA has a valid CRL with no entries.
	rootCAID, err := database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate)
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	rootCA, err := database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err := db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}

	// The intermediate CA has no CRL.
	intermediateCAID, err := database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "")
	if err != nil {
		t.Fatalf("Couldn't create certificate authority: %s", err)
	}
	intermediateCA, err := database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL != "" {
		t.Fatalf("CRL available for a CA without a certificate")
	}

	// The signed intermediate CA has a valid and empty CRL,
	// and its certificate has a CRLDistributionPoint extension that points to the root CA's CRL.
	err = database.SignCertificateRequest(db.ByCSRPEM(IntermediateCACSR), db.ByCertificateAuthorityID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	if intermediateCA.CRL == "" {
		t.Fatalf("CRL not available for a CA with a certificate")
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has unexpected entry")
	}
	certs, err := db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The signed CSR has a CRLDistributionPoint extension that points to the Intermediate CA's CRL with the correct hostname.
	csrID, err := database.CreateCertificateRequest(AppleCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(intermediateCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err := database.GetCertificateRequestAndChain(db.ByCSRPEM(AppleCSR))
	if err != nil {
		t.Fatalf("Couldn't get CSR: %s", err)
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/2/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/2/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the intermediate CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	AppleCertSerial := certs[0].SerialNumber.String()
	intermediateCA, err = database.GetDenormalizedCertificateAuthority(db.ByCertificateAuthorityID(intermediateCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(intermediateCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != AppleCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", AppleCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The signed certificate has a CRLDistributionPoint extension that points to the root CA's CRL with the correct hostname.
	csrID, err = database.CreateCertificateRequest(StrawberryCSR)
	if err != nil {
		t.Fatalf("Couldn't create CSR: %s", err)
	}
	err = database.SignCertificateRequest(db.ByCSRID(csrID), db.ByCertificateAuthorityID(rootCAID), "example.com")
	if err != nil {
		t.Fatalf("Couldn't sign certificate authority: %s", err)
	}
	csr, err = database.GetCertificateRequestAndChain(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't get csr: %s", err)
	}
	if strings.Count(csr.CertificateChain, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("Expected end certificate chain to be 2 certificates long.")
	}
	certs, err = db.ParseCertificateChain(csr.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	if certs[0].CRLDistributionPoints[0] != "https://example.com/api/v1/certificate_authorities/1/crl" {
		t.Fatalf("CRLDistributionPoint extension false: expected https://example.com/api/v1/certificate_authorities/1/crl but got %s", certs[0].CRLDistributionPoints[0])
	}

	// The revoked certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRID(csrID))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	StrawberryCertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL should have 1 entry, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", StrawberryCertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}

	// The revoked intermediate CA's certificate's serial number is placed in the root CA CRL
	err = database.RevokeCertificate(db.ByCSRPEM(intermediateCA.CSRPEM))
	if err != nil {
		t.Fatalf("Couldn't revoke csr: %s", err)
	}
	certs, err = db.ParseCertificateChain(intermediateCA.CertificateChain)
	if err != nil {
		t.Fatalf("Couldn't parse certificate chain: %s", err)
	}
	IntermediateCACertSerial := certs[0].SerialNumber.String()
	rootCA, err = database.GetCertificateAuthority(db.ByCertificateAuthorityID(rootCAID))
	if err != nil {
		t.Fatalf("Couldn't get certificate authority: %s", err)
	}
	crl, err = db.ParseCRL(rootCA.CRL)
	if err != nil {
		t.Fatalf("Couldn't parse certificate revocation list: %s", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL should have 2 entries, but has %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.String() != StrawberryCertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
	if crl.RevokedCertificateEntries[1].SerialNumber.String() != IntermediateCACertSerial {
		t.Fatalf("CRL should have serial %s, but has %s", IntermediateCACertSerial, crl.RevokedCertificateEntries[0].SerialNumber.String())
	}
}
