package metrics_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/db"
	metrics "github.com/canonical/notary/internal/metrics"
	"go.uber.org/zap"
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
)

// TestPrometheusHandler tests that the Prometheus metrics handler responds correctly to an HTTP request.
func TestPrometheusHandler(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()

	request, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	if !strings.Contains(recorder.Body.String(), "go_goroutines") {
		t.Errorf("handler returned an empty body")
	}
	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Generates a CSR and Certificate with the given days remaining
func generateCertPair(daysRemaining int) (string, string, string) {
	NotAfterTime := time.Now().AddDate(0, 0, daysRemaining)
	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	csrTemplate := x509.CertificateRequest{}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotAfter:     NotAfterTime,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, certKey)
	caBytes, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	caCertificate, _ := x509.ParseCertificate(caBytes)
	certBytes, _ := x509.CreateCertificate(rand.Reader, &certTemplate, caCertificate, &certKey.PublicKey, caKey)

	var buff bytes.Buffer
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	csr := buff.String()
	buff.Reset()
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	cert := buff.String()
	buff.Reset()
	pem.Encode(&buff, &pem.Block{ //nolint:errcheck
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	ca := buff.String()
	return csr, cert, ca
}

func initializeTestDBWithCerts(t *testing.T, database *db.Database) {
	userID, err := database.CreateUser("testuser", "whateverPassword", 0)
	if err != nil {
		t.Fatalf("couldn't create test user: %s", err)
	}
	for _, v := range []int{5, 10, 32} {
		csr, cert, ca := generateCertPair(v)
		csrID, err := database.CreateCertificateRequest(csr, userID)
		if err != nil {
			t.Fatalf("couldn't create test csr: %s", err)
		}
		_, err = database.AddCertificateChainToCertificateRequest(db.ByCSRID(csrID), fmt.Sprintf("%s%s", cert, ca))
		if err != nil {
			t.Fatalf("couldn't create test cert: %s", err)
		}
	}
}

func initializeTestDBWithCaCerts(t *testing.T, database *db.Database) {
	// Create user
	userID, err := database.CreateUser("testuser", "whateverPassword", 0)
	if err != nil {
		t.Fatalf("couldn't create test user: %s", err)
	}
	// create an active ca
	_, err = database.CreateCertificateAuthority(RootCACSR, RootCAPrivateKey, RootCACRL, RootCACertificate+"\n"+RootCACertificate, userID)
	if err != nil {
		t.Fatalf("couldn't create self signed ca: %s", err)
	}
	// create a pending ca
	_, err = database.CreateCertificateAuthority(IntermediateCACSR, IntermediateCAPrivateKey, "", "", userID)
	if err != nil {
		t.Fatalf("couldn't create pending ca: %s", err)
	}
}

// TestMetrics tests some of the metrics that we currently collect.
func TestCertificateMetrics(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	initializeTestDBWithCerts(t, db)
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()
	csrs, _ := db.ListCertificateRequestWithCertificates()
	m.GenerateCertificateMetrics(csrs)

	request, _ := http.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}
	expectedMetrics := map[string]struct{}{
		"outstanding_certificate_requests": {},
		"certificate_requests":             {},
		"certificates":                     {},
		"certificates_expired":             {},
		"certificates_expiring_in_1_day":   {},
		"certificates_expiring_in_7_days":  {},
		"certificates_expiring_in_30_days": {},
		"certificates_expiring_in_90_days": {},
	}

	foundMetrics := make(map[string]bool)

	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}

		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "outstanding_certificate_requests ") {
			foundMetrics["outstanding_certificate_requests"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("outstanding_certificate_requests expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificate_requests ") {
			foundMetrics["certificate_requests"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificate_requests expected to receive 3")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates ") {
			foundMetrics["certificates"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates expected to receive 3")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expired ") {
			foundMetrics["certificates_expired"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expired expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_1_day ") {
			foundMetrics["certificates_expiring_in_1_day"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("certificates_expiring_in_1_day expected to receive 0")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_7_days ") {
			foundMetrics["certificates_expiring_in_7_days"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("certificates_expiring_in_7_days expected to receive 1")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_30_days ") {
			foundMetrics["certificates_expiring_in_30_days"] = true
			if !strings.HasSuffix(line, "2") {
				t.Errorf("certificates_expiring_in_30_days expected to receive 2")
			}
		} else if strings.HasPrefix(trimmedLine, "certificates_expiring_in_90_days ") {
			foundMetrics["certificates_expiring_in_90_days"] = true
			if !strings.HasSuffix(line, "3") {
				t.Errorf("certificates_expiring_in_90_days expected to receive 3")
			}
		}
	}

	// Verify all expected metrics were found
	for metric := range expectedMetrics {
		if !foundMetrics[metric] {
			t.Errorf("Expected metric %s not found in metrics output", metric)
		}
	}

	err = db.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCACertificateMetrics(t *testing.T) {
	tempDir := t.TempDir()
	db, err := db.NewDatabase(filepath.Join(tempDir, "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	initializeTestDBWithCaCerts(t, db)
	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("cannot create logger: %s", err)
	}
	m := metrics.NewMetricsSubsystem(db, l)
	defer m.Close()
	cas, err := db.ListDenormalizedCertificateAuthorities()
	if err != nil {
		t.Fatalf("couldn't list denormalized certificate authorities: %s", err)
	}
	m.GenerateCACertificateMetrics(cas)

	request, _ := http.NewRequest("GET", "/", nil)
	recorder := httptest.NewRecorder()
	m.Handler.ServeHTTP(recorder, request)

	if status := recorder.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if recorder.Body.String() == "" {
		t.Errorf("handler returned an empty body")
	}

	foundMetrics := map[string]bool{
		"active_ca_certificates":  false,
		"expired_ca_certificates": false,
		"pending_ca_certificates": false,
		"legacy_ca_certificates":  false,
	}

	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "active_ca_certificates ") {
			foundMetrics["active_ca_certificates"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("Expected active_ca_certificates to be 1, got %s", line)
			}
		} else if strings.HasPrefix(trimmedLine, "expired_ca_certificates ") {
			foundMetrics["expired_ca_certificates"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("Expected expired_ca_certificates to be 0, got %s", line)
			}
		} else if strings.HasPrefix(trimmedLine, "pending_ca_certificates ") {
			foundMetrics["pending_ca_certificates"] = true
			if !strings.HasSuffix(line, "1") {
				t.Errorf("Expected pending_ca_certificates to be 1, got %s", line)
			}
		} else if strings.HasPrefix(trimmedLine, "legacy_ca_certificates ") {
			foundMetrics["legacy_ca_certificates"] = true
			if !strings.HasSuffix(line, "0") {
				t.Errorf("Expected legacy_ca_certificates to be 0, got %s", line)
			}
		}
	}

	// Verify all expected metrics were found
	for metric, found := range foundMetrics {
		if !found {
			t.Errorf("Expected metric %s not found in output", metric)
		}
	}
}
