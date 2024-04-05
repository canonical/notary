package certificates_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/canonical/gocert/internal/certificates"
)

const (
	ValidCert1 = `-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwJzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD0Nhbm9uaWNhbCwgSU5DLjAeFw0yNDA0MDUxMDAzMjhaFw0zNDA0
MDUxMDAzMjhaMCcxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9DYW5vbmljYWwsIElO
Qy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGiemPRVW7GhnSmbXh
PJz90+mvByoyYIaw+ILlcCvkJolYP4DzO5upME8mBQY8F+YDh0XfC7bGIMyK3XHL
wivglUXU4i3VzpOrwZ4THomCKroTE9o5X0rpS4xjILXRNLOE3Je2GqGEpQYS8ad0
wHsmdgBACYw2skdgXjqbDkr6y2J1QHG8TCQfwijLpZQJhBFflAT1wm4gl+AKSpTj
isrmsxFJpvlJI9RnhhEY8pDsrUruiwZ6pJ36p79e0r8m+6Rs36fYx7FsTRI5VBCR
H9WvyA2W1xukEh1T0KB3Sy8Omb8ySNp7H5/9/wH4HZQy4tfpQt3MA6kretL2Xp0G
AodZAgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcD
AgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUYEQDVgZidxvS
pph/+NWsxWRVA20wDQYJKoZIhvcNAQELBQADggEBAIJb2BeiquR05bDh2t831BCq
EteqhgQoKclZXjCYYyWNGaClXngIHOJhx4WVsNIhRJmscdbJFWbBm0z6UQe0kLU3
6cAQJlOy/7u5I6jIjyETLqLP8SgVaPuCEWyX82LVRm87OjzTZSQqhTh/gMpU/OdK
BwFENLc7LcWQ1eqBeeBjP5HhaC2BtSENVHBh81mKpR4mQBOoKq71XszSuqTQPkE5
x/OFl3VkxM8x1aAdSK/V5UR8IlIbDW/dDQwsPoPBr5K/YuxUnm0GD6Ycqz7k/4F/
R6grKY9bPkxtGvwIw1BqM7sqJ77knkLXRj4mH3J6znjY9dVLSKRjcZLMBtKhlr0=
-----END CERTIFICATE-----`
	ValidCert2 = `-----BEGIN CERTIFICATE-----
MIIELjCCAxagAwIBAgICBnowDQYJKoZIhvcNAQELBQAwJzELMAkGA1UEBhMCVVMx
GDAWBgNVBAoTD0Nhbm9uaWNhbCwgSU5DLjAeFw0yNDA0MDUxMDAzMjhaFw0zNDA0
MDUxMDAzMjhaMCcxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9DYW5vbmljYWwsIElO
Qy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDAP98jcfNw40HbS1xR
6UpSQTp4AGldFWQZBOFaVzD+eh7sYM/BFdT0dZRHGjXxL77ewDbwdwAFJ5zuxo+u
8/VgKGRpK6KCnKailmVrdRDhA45airMRQN6QXurN4NZgXcCHJWGAQKA9XJzcwGJF
l5LxoFY58wCv0d1JP8fgmbcgIRQTCIvhrlgrJ5Acz9QP6BuaxEHKbYYvWyTWtAhi
HS/w51yEbh6959ceJGBDZPyEVd9sfGipvHrA73+33+XBluRcUuWV4dCecyP/m+8C
jTBmW5s8gS6JUDE8yl99qm7CnXTkNDqPXThrorcKRwcHrw3ZEOm5rUPLuyzGBx/C
DZUbY9bsvHJMHOHlbwiY+M2MFIO+3H6qyfPfcHs8NFkrZh/as+9hrEzSYcz+tGBi
NynkSmNPQi4yzT00ilKYgcBhPdDDlBbdhcmdeFA3XE880VkQdJgefsYpCgYRdILm
DDd6ZMfZsQOJjuRC8rQKLO+z1X5JhiOlkNxZaOkq9b9eu7230rxTFCGocn0l9oKw
0q8OIDOTb7UKdIaGq/y++uRxe0hhNoijN1OJvh+R3/KGuztu5Y8ejksIxKBrUqCg
bUDXmQ82xbdJ36qF+NHBqFqFaKhH1XuK6eAIfqgQam/u9HNZZw3mOdm9rvIZfwIT
F9gvSwm1bxzyIHL/zWOgyfzckQIDAQABo2QwYjAOBgNVHQ8BAf8EBAMCB4AwHQYD
VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDgQHBAUBAgMEBjAhBgNV
HREEGjAYhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IB
AQB4UEu1/vTpEuuwoqgFpp8tEMewwBQ/CXPBN5seDnd/SUMXFrxk58f498qI3FQy
q98a+89jPWRGA5LY+DfIS82NYCwbKuvTzuJRoUpMPbebrhu7OQl7qQT6n8VOCy6x
IaRnPI0zEGbg2v340jMbB26FiyaFKyHEc24nnq3suZFmbslXzRE2Ebut+Qtft8he
0pSNQXtz5ULt0c8DTje7j+mRABzus45cj3HMDO4vcVRrHegdTE8YcZjwAFTKxqpg
W7GwJ5qPjnm6EMe8da55m8Q0hZchwGZreXNG7iCaw98pACBNgOOxh4LOhEZy25Bv
ayrvWnmPfg1u47sduuhHeUid
-----END CERTIFICATE-----`
	ValidPK1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxonpj0VVuxoZ0pm14Tyc/dPprwcqMmCGsPiC5XAr5CaJWD+A
8zubqTBPJgUGPBfmA4dF3wu2xiDMit1xy8Ir4JVF1OIt1c6Tq8GeEx6Jgiq6ExPa
OV9K6UuMYyC10TSzhNyXthqhhKUGEvGndMB7JnYAQAmMNrJHYF46mw5K+stidUBx
vEwkH8Ioy6WUCYQRX5QE9cJuIJfgCkqU44rK5rMRSab5SSPUZ4YRGPKQ7K1K7osG
eqSd+qe/XtK/JvukbN+n2MexbE0SOVQQkR/Vr8gNltcbpBIdU9Cgd0svDpm/Mkja
ex+f/f8B+B2UMuLX6ULdzAOpK3rS9l6dBgKHWQIDAQABAoIBAQCJcpLSUCLw/Dni
Ve3Xt/nLtDi0ppYs+CxnOjSMmOKZ+Z/eC2C/g4XZVIuG+7V8RuNDkBPsPZTUh4Jz
pKkSciOkQFNu9QLcYT5Uix9fhyWVivT1HipWy8T1zAqt2chlxEF/+qPBO6CUTxbs
aIYQyuy3DLxRmQqMF1JYwgN6syNvicQ0rbpsX0/svmpaKEd+YLUy8l06MtSPnj0N
RWoUm2pWbCAFzHfeMUjTbyjeIQgbok1HGFtxuaO25TjPFB+MtZKwIe90NYFasCDO
GCR0wPsgFCzygi/68CycCfwSfQUW/xIQznpa69ifwA0Zwpf1GWeAClmN+/3vP3sI
dMXk9GPNAoGBAN1+MqbPmRNwMsEBZrzprsYF78lUB28iPn9HgbeXir5NpelzJxjh
oL0BRl9TmTgSFPS4baKMrLJPjPP0xk330E195/14lEf29i3Zis5W0d5UN9J3nta3
nx1iJ8RZmyyPRHb0KEjftSp3nR68OTAQa9oCxKVsf8IsxhxfZM3bQiFrAoGBAOV4
Ow4hXHhUhjUz86QKTnA8fWgkKL9HAc9r/EOzPGC0Ng39mS867NoV2cqfuHni3r+X
edlNO9dI/WZF52nQ9q1WNUEcZBuqeI07bVGddgtwQ3jUJbVuifG35qSmF2FfryXb
2GhXmVxsnwMkgwuAF57+QQC1kF9W95ioRsN4zndLAoGAZs5Tjk+fWoFiXWlcGWVR
xQIuaUFCbhfz8DntgJyrPmdmEfRr+kWHyRKValuwK3FhHrGX2bH32o/H+dfsT3Yt
zjoZevIDyV9cpq1pmxp7MPngKyVwqXLzPL05fg6lUspw2dG7/Q8w1LROTlzJIoEM
vlU4lxvENQl5LuQsMsyJZl8CgYA/8S7TkyxHQ5ZaQO3FajHNSK3RVTIditXQTNDw
tINAlzbw0xfad1sEsk4MDlHDdRqI3NbRXJouNWKXGyeO7vGt/3W7fQPQScJp6INf
2LbKHTBP/R283t6Fgq88diPRuG3/6LD28mIDxSjSIVx62ei7HzJR1kYyqvM3kLyX
P5SY3QKBgQC0oL1GX4iteb9uzfGsknrlYf9Eid9zLbc7MFEZ+JdQECNUrqAg6vt3
0X3rDNjY2R0UZEC14WSx+Ax7xuSrozEtnuU6dBMv9wqCpJ36go+1TPwoe29uxJa5
AqfiZgKPTXDLu0RPIeHUwyygzauy9FfeMGP+YjmGpJdONIDXf1npqg==
-----END RSA PRIVATE KEY-----`
	ValidPK2 = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
)

func TestParseCertificateSuccess(t *testing.T) {
	cert, err := certificates.ParseCertificate(ValidCert1)
	if err != nil {
		t.Fatalf("couldn't parse certificate: %s", err)
	}
	if cert.Issuer.Organization[0] != "Canonical, INC." {
		t.Fatalf("certificate was parsed incorrectly")
	}
}

func TestParseCertificateFail(t *testing.T) {
	var wrongString = "this is a real cert!!!"
	var wrongStringErr = "PEM Certificate string not found or malformed"
	var ValidCertWithoutWhitespace = strings.ReplaceAll(ValidCert1, "\n", "")
	var ValidCertWithoutWhitespaceErr = "PEM Certificate string not found or malformed"
	var wrongPemType = strings.ReplaceAll(ValidCert1, "CERTIFICATE", "SOME RANDOM PEM TYPE")
	var wrongPemTypeErr = "given PEM string not a certificate"

	cases := []struct {
		input       string
		expectedErr string
	}{
		{
			input:       wrongString,
			expectedErr: wrongStringErr,
		},
		{
			input:       ValidCertWithoutWhitespace,
			expectedErr: ValidCertWithoutWhitespaceErr,
		},
		{
			input:       wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			_, err := certificates.ParseCertificate(c.input)
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestParsePKCS1PrivateKeySuccess(t *testing.T) {
	pk, err := certificates.ParsePKCS1PrivateKey(ValidPK1)
	if err != nil {
		t.Fatalf("couldn't parse private key: %s", err)
	}
	if pk.E != 65537 {
		t.Fatalf("private key was parsed incorrectly")
	}
}

func TestParsePKCS1PrivateKeyFail(t *testing.T) {
	var wrongString = "this is a real pk!!!"
	var wrongStringErr = "PEM private key string not found or malformed"
	var ValidCertWithoutWhitespace = strings.ReplaceAll(ValidCert1, "\n", "")
	var ValidCertWithoutWhitespaceErr = "PEM private key string not found or malformed"
	var wrongPemType = strings.ReplaceAll(ValidCert1, "RSA PRIVATE KEY", "SOME RANDOM PEM TYPE")
	var wrongPemTypeErr = "given PEM string not an rsa private key"

	cases := []struct {
		input       string
		expectedErr string
	}{
		{
			input:       wrongString,
			expectedErr: wrongStringErr,
		},
		{
			input:       ValidCertWithoutWhitespace,
			expectedErr: ValidCertWithoutWhitespaceErr,
		},
		{
			input:       wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidPK%d", i), func(t *testing.T) {
			_, err := certificates.ParsePKCS1PrivateKey(c.input)
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}
func TestGenerateCACertificateSuccess(t *testing.T) {
	caCertPEM, caPKPEM, err := certificates.GenerateCACertificate()
	if err != nil {
		t.Fatalf("could not generate CA cert and PK")
	}
	if _, err := certificates.ParseCertificate(caCertPEM); err != nil {
		t.Fatalf("generate CA cert cannot be parsed")
	}
	if _, err := certificates.ParsePKCS1PrivateKey(caPKPEM); err != nil {
		t.Fatalf("generate CA private key cannot be parsed")
	}
}

func TestGenerateSelfSignedCertificateSuccess(t *testing.T) {
	caCertPEM, caPKPEM, _ := certificates.GenerateCACertificate()
	cert, pk, genErr := certificates.GenerateSelfSignedCertificate(caCertPEM, caPKPEM)
	_, certErr := certificates.ParseCertificate(cert)
	_, keyErr := certificates.ParsePKCS1PrivateKey(pk)
	if genErr != nil || certErr != nil || keyErr != nil {
		t.Fatalf("couldn't generate self signed certificate")
	}
}

func TestGenerateSelfSignedCertificateFail(t *testing.T) {
	var nonMatchingCertPKErr = "x509: provided PrivateKey doesn't match parent's PublicKey"

	cases := []struct {
		caCert      string
		caPK        string
		expectedErr string
	}{
		{
			caCert:      ValidCert1,
			caPK:        ValidPK2,
			expectedErr: nonMatchingCertPKErr,
		},
		// Help: Why is this passing?
		// {
		// 	caCert:      ValidCert2,
		// 	caPK:        ValidPK2,
		// 	expectedErr: notCAErr,
		// },
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("SelfSignedCertificateFails%d", i), func(t *testing.T) {
			_, _, err := certificates.GenerateSelfSignedCertificate(c.caCert, c.caPK)
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}
