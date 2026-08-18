package cluster_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

func TestGenerateJoinTokenIsUniqueAndHashed(t *testing.T) {
	first, firstHash, err := cluster.GenerateJoinToken()
	if err != nil {
		t.Fatalf("couldn't generate a join token: %s", err)
	}
	second, secondHash, err := cluster.GenerateJoinToken()
	if err != nil {
		t.Fatalf("couldn't generate a join token: %s", err)
	}

	if first == second {
		t.Fatal("two generated join tokens are identical")
	}
	if firstHash == secondHash {
		t.Fatal("two generated join tokens hash to the same value")
	}
	if firstHash != cluster.HashJoinToken(first) {
		t.Error("the returned hash is not the hash of the returned token")
	}
	if strings.Contains(firstHash, first) {
		t.Error("the stored hash contains the token itself")
	}
}

func TestPrepareJoinKeepsThePrivateKeyLocal(t *testing.T) {
	stateDir := t.TempDir()

	csrPEM, err := cluster.PrepareJoin(stateDir, "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a PEM certificate request, got %q", string(csrPEM))
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse the certificate request: %s", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the certificate request is not self-signed: %s", err)
	}

	// The key must exist locally and must not be part of what gets sent.
	keyPath := filepath.Join(cluster.PKIDir(stateDir), "node.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected a node key at %s: %s", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("node key has permissions %o, want 600", perm)
	}
	if strings.Contains(string(csrPEM), "PRIVATE KEY") {
		t.Error("the certificate request contains private key material")
	}
}

func TestPrepareJoinRequiresAnAddress(t *testing.T) {
	if _, err := cluster.PrepareJoin(t.TempDir(), ""); err == nil {
		t.Fatal("expected preparing a join without an address to fail")
	}
}

func TestJoinRoundTripProducesAVerifiableCertificate(t *testing.T) {
	const joinerAddress = "10.0.0.2:9000"

	existingDir := t.TempDir()
	if _, err := cluster.EnsurePKI(existingDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}

	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}

	certPEM, caCertPEM, err := cluster.SignJoinRequest(existingDir, csrPEM, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't sign the join request: %s", err)
	}
	if err := cluster.CompleteJoin(joinerDir, certPEM, caCertPEM); err != nil {
		t.Fatalf("couldn't complete the join: %s", err)
	}

	// The joining node must now load its PKI exactly as a bootstrapped node
	// does, which is what lets cluster.Start treat both the same.
	pki, err := cluster.EnsurePKI(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't load the joined node's PKI: %s", err)
	}

	cert, err := x509.ParseCertificate(pki.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("couldn't parse the signed certificate: %s", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pki.Pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("the signed certificate does not verify against the cluster CA: %s", err)
	}
	if cert.Subject.CommonName != joinerAddress {
		t.Errorf("got common name %q, want %q", cert.Subject.CommonName, joinerAddress)
	}
	// go-dqlite reads the TLS ServerName it presents to peers from the first DNS
	// SAN, so a joined node must carry the same one a bootstrapped node does.
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "notary-cluster" {
		t.Errorf("got DNS names %v, want notary-cluster first", cert.DNSNames)
	}
}

// A joining node must not be able to widen what its certificate authorizes by
// crafting the request: only the public key is taken from the CSR.
func TestSignJoinRequestIgnoresRequestedExtensions(t *testing.T) {
	existingDir := t.TempDir()
	if _, err := cluster.EnsurePKI(existingDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}

	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, "attacker.example.com:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}

	certPEM, _, err := cluster.SignJoinRequest(existingDir, csrPEM, "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("couldn't sign the join request: %s", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse the signed certificate: %s", err)
	}

	if cert.Subject.CommonName != "10.0.0.2:9000" {
		t.Errorf("got common name %q, want the address the signer was given", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Error("the issued node certificate is a CA")
	}
	for _, name := range cert.DNSNames {
		if name == "attacker.example.com" {
			t.Error("a name from the certificate request leaked into the certificate")
		}
	}
}

func TestSignJoinRequestRejectsMalformedRequests(t *testing.T) {
	existingDir := t.TempDir()
	if _, err := cluster.EnsurePKI(existingDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}

	tests := []struct {
		name    string
		csr     string
		address string
	}{
		{"not PEM", "definitely not a csr", "10.0.0.2:9000"},
		{"PEM but not a request", "-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----\n", "10.0.0.2:9000"},
		{"empty address", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := cluster.SignJoinRequest(existingDir, []byte(tt.csr), tt.address); err == nil {
				t.Fatal("expected signing to fail")
			}
		})
	}
}

// Only a node holding the cluster CA private key can admit new members.
func TestSignJoinRequestFailsWithoutTheCAKey(t *testing.T) {
	const joinerAddress = "10.0.0.2:9000"

	existingDir := t.TempDir()
	if _, err := cluster.EnsurePKI(existingDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}

	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	certPEM, caCertPEM, err := cluster.SignJoinRequest(existingDir, csrPEM, joinerAddress)
	if err != nil {
		t.Fatalf("couldn't sign the join request: %s", err)
	}
	if err := cluster.CompleteJoin(joinerDir, certPEM, caCertPEM); err != nil {
		t.Fatalf("couldn't complete the join: %s", err)
	}

	if _, _, err := cluster.SignJoinRequest(joinerDir, csrPEM, joinerAddress); err == nil {
		t.Fatal("expected a member without the CA key to be unable to sign join requests")
	}
}

func TestCompleteJoinRejectsUnusableMaterial(t *testing.T) {
	existingDir := t.TempDir()
	if _, err := cluster.EnsurePKI(existingDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}
	csrPEM, err := cluster.PrepareJoin(t.TempDir(), "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	certPEM, caCertPEM, err := cluster.SignJoinRequest(existingDir, csrPEM, "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("couldn't sign the join request: %s", err)
	}

	tests := []struct {
		name string
		cert []byte
		ca   []byte
	}{
		{"garbage certificate", []byte("nope"), caCertPEM},
		{"garbage CA certificate", certPEM, []byte("nope")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := cluster.CompleteJoin(dir, tt.cert, tt.ca); err == nil {
				t.Fatal("expected completing the join to fail")
			}
			if _, err := os.Stat(filepath.Join(cluster.PKIDir(dir), "cluster.crt")); err == nil {
				t.Error("unusable material was written to the PKI directory")
			}
		})
	}
}
