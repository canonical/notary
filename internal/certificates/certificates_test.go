package certificates_test

import (
	"testing"

	"github.com/canonical/gocert/internal/certificates"
)

func TestGenerateSelfSignedCertificateSuccess(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func TestGenerateSelfSignedCertificateFail(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func TestParseCertificateSuccess(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func TestParseCertificateFail(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func TestParsePKCS1PrivateKeySuccess(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

		})
	}
}

func TestParsePKCS1PrivateKeyFail(t *testing.T) {
	testCases := []struct {
		desc string
	}{
		{
			desc: "",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {

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
