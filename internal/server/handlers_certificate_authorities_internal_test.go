package server

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parseTestCertificate(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	return cert
}

func parseTestCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}
	return csr
}

func TestCreateSelfSignedCAWithOnlyCommonName(t *testing.T) {
	_, _, _, certPEM, err := createCertificateAuthority(CreateCertificateAuthorityParams{
		SelfSigned: true,
		CommonName: "test-ca",
	})
	if err != nil {
		t.Fatalf("couldn't create certificate authority: %s", err)
	}

	cert := parseTestCertificate(t, certPEM)
	if got := cert.Subject.String(); got != "CN=test-ca" {
		t.Fatalf("expected subject CN=test-ca, got %s", got)
	}
	if got := cert.Issuer.String(); got != "CN=test-ca" {
		t.Fatalf("expected issuer CN=test-ca, got %s", got)
	}
}

func TestCreateIntermediateCAWithOnlyCommonName(t *testing.T) {
	csrPEM, _, _, certPEM, err := createCertificateAuthority(CreateCertificateAuthorityParams{
		SelfSigned: false,
		CommonName: "test-ca",
	})
	if err != nil {
		t.Fatalf("couldn't create certificate authority: %s", err)
	}
	if certPEM != "" {
		t.Fatalf("expected no certificate for an intermediate CA")
	}

	csr := parseTestCSR(t, csrPEM)
	if got := csr.Subject.String(); got != "CN=test-ca" {
		t.Fatalf("expected subject CN=test-ca, got %s", got)
	}
	if len(csr.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs, got %q", csr.DNSNames)
	}
}

func TestCreateCAKeepsProvidedSubjectFields(t *testing.T) {
	csrPEM, _, _, certPEM, err := createCertificateAuthority(CreateCertificateAuthorityParams{
		SelfSigned:          true,
		CommonName:          "test-ca",
		SANsDNS:             "ca.example.com",
		CountryName:         "TR",
		StateOrProvinceName: "Istanbul",
		LocalityName:        "Kadikoy",
		OrganizationName:    "Canonical",
		OrganizationalUnit:  "Identity",
	})
	if err != nil {
		t.Fatalf("couldn't create certificate authority: %s", err)
	}

	want := "CN=test-ca,OU=Identity,O=Canonical,L=Kadikoy,ST=Istanbul,C=TR"
	if got := parseTestCertificate(t, certPEM).Subject.String(); got != want {
		t.Fatalf("expected certificate subject %s, got %s", want, got)
	}
	csr := parseTestCSR(t, csrPEM)
	if got := csr.Subject.String(); got != want {
		t.Fatalf("expected CSR subject %s, got %s", want, got)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "ca.example.com" {
		t.Fatalf("expected DNS SANs [ca.example.com], got %q", csr.DNSNames)
	}
}
