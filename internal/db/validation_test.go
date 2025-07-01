package db_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
)

func TestCSRValidationSuccess(t *testing.T) {
	cases := []string{tu.AppleCSR, tu.BananaCSR, tu.StrawberryCSR}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCSR%d", i), func(t *testing.T) {
			if err := db.ValidateCertificateRequest(c); err != nil {
				t.Errorf("Couldn't verify valid CSR: %s", err)
			}
		})
	}
}

func TestCSRValidationFail(t *testing.T) {
	wrongString := "this is a real csr!!!"
	wrongStringErr := errors.New("PEM Certificate Request string not found or malformed")
	ValidCSRWithoutWhitespace := strings.ReplaceAll(tu.AppleCSR, "\n", "")
	ValidCSRWithoutWhitespaceErr := errors.New("PEM Certificate Request string not found or malformed")
	wrongPemType := strings.ReplaceAll(tu.AppleCSR, "CERTIFICATE REQUEST", "SOME RANDOM PEM TYPE")
	wrongPemTypeErr := errors.New("given PEM string not a certificate request")
	InvalidCSR := strings.ReplaceAll(tu.AppleCSR, "s", "p")
	InvalidCSRErr := errors.New("asn1: syntax error: data truncated")

	cases := []struct {
		input       string
		expectedErr error
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
			err := db.ValidateCertificateRequest(c.input)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if errors.Is(err, c.expectedErr) {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestCertValidationSuccess(t *testing.T) {
	cases := []string{
		fmt.Sprintf("%s\n%s", tu.BananaCert, tu.IntermediateCert),
		fmt.Sprintf("%s\n%s\n%s", tu.BananaCert, tu.IntermediateCert, tu.RootCert),
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCert%d", i), func(t *testing.T) {
			if err := db.ValidateCertificate(c); err != nil {
				t.Errorf("Couldn't verify valid Cert: %s", err)
			}
		})
	}
}

func TestCertValidationFail(t *testing.T) {
	wrongCertString := "this is a real cert!!!"
	wrongCertStringErr := errors.New("less than 2 certificate PEM strings were found")
	wrongPemType := strings.ReplaceAll(tu.BananaCert, "CERTIFICATE", "SOME RANDOM PEM TYPE")
	wrongPemTypeErr := errors.New("a given PEM string was not a certificate")
	InvalidCert := strings.ReplaceAll(tu.BananaCert, "M", "i")
	InvalidCertErr := errors.New("x509: malformed certificate")
	singleCert := tu.BananaCert
	singleCertErr := errors.New("less than 2 certificate PEM strings were found")
	issuerCertSubjectDoesNotMatch := fmt.Sprintf("%s\n%s", tu.BananaCert, tu.WrongSubjectIssuerCert)
	issuerCertSubjectDoesNotMatchErr := errors.New("invalid certificate chain: certificate 0, certificate 1: subjects do not match")
	issuerCertNotCA := fmt.Sprintf("%s\n%s", tu.BananaCert, tu.UnusedCert)
	issuerCertNotCaErr := errors.New("invalid certificate chain: certificate 1 is not a certificate authority")

	cases := []struct {
		inputCert   string
		expectedErr error
	}{
		{
			inputCert:   wrongCertString,
			expectedErr: wrongCertStringErr,
		},
		{
			inputCert:   wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
		{
			inputCert:   InvalidCert,
			expectedErr: InvalidCertErr,
		},
		{
			inputCert:   singleCert,
			expectedErr: singleCertErr,
		},
		{
			inputCert:   issuerCertSubjectDoesNotMatch,
			expectedErr: issuerCertSubjectDoesNotMatchErr,
		},
		{
			inputCert:   issuerCertNotCA,
			expectedErr: issuerCertNotCaErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.ValidateCertificate(c.inputCert)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if errors.Is(err, c.expectedErr) {
				t.Errorf("Expected error not found:\nReceived: %s\n Expected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestCertificateMatchesCSRSuccess(t *testing.T) {
	cases := []struct {
		inputCSR  string
		inputCert string
	}{
		{
			inputCSR:  tu.BananaCSR,
			inputCert: fmt.Sprintf("%s\n%s", tu.BananaCert, tu.IntermediateCert),
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.CertificateMatchesCSR(c.inputCert, c.inputCSR)
			if err != nil {
				t.Errorf("Certificate did not match when it should have")
			}
		})
	}
}

func TestCertificateMatchesCSRFail(t *testing.T) {
	certificateDoesNotMatchErr := "certificate does not match CSR"

	cases := []struct {
		inputCSR    string
		inputCert   string
		expectedErr string
	}{
		{
			inputCSR:    tu.AppleCSR,
			inputCert:   fmt.Sprintf("%s\n%s", tu.BananaCert, tu.IntermediateCert),
			expectedErr: certificateDoesNotMatchErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.CertificateMatchesCSR(c.inputCert, c.inputCSR)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\n Expected: %s", err, c.expectedErr)
			}
		})
	}
}
