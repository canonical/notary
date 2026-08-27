package cluster_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/cluster"
	tu "github.com/canonical/notary/internal/testutils"
)

func nodeCertificate(t *testing.T, pki *cluster.PKI) *x509.Certificate {
	t.Helper()

	if len(pki.Certificate.Certificate) == 0 {
		t.Fatal("PKI has no node certificate")
	}
	cert, err := x509.ParseCertificate(pki.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse node certificate: %v", err)
	}

	return cert
}

func TestLoadPKIReadsProvisionedMaterial(t *testing.T) {
	stateDir := t.TempDir()
	tu.WriteProvisionedPKI(t, stateDir, "10.0.0.1:7000")

	pki, err := cluster.LoadPKI(stateDir)
	if err != nil {
		t.Fatalf("LoadPKI returned an error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(cluster.PKIDir(stateDir), "cluster.key")); err == nil {
		t.Error("provisioned PKI must not include a cluster CA private key")
	}

	cert := nodeCertificate(t, pki)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pki.Pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("node certificate does not verify against the cluster CA: %v", err)
	}
	if err := pki.MatchesIdentity("10.0.0.1:7000"); err != nil {
		t.Errorf("certificate should match the provisioned address: %v", err)
	}
}

func TestLoadPKIRequiresSharedDNSSANFirst(t *testing.T) {
	stateDir := t.TempDir()
	tu.WriteProvisionedPKI(t, stateDir, "10.0.0.1:7000")

	pki, err := cluster.LoadPKI(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	cert := nodeCertificate(t, pki)
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "notary-cluster" {
		t.Fatalf("first DNS SAN is %v, want notary-cluster", cert.DNSNames)
	}
}

func TestLoadPKIRejectsMissingFiles(t *testing.T) {
	if _, err := cluster.LoadPKI(t.TempDir()); err == nil {
		t.Fatal("expected LoadPKI to reject a directory with no PKI")
	}
}

func TestLoadPKIRejectsWorldReadableNodeKey(t *testing.T) {
	stateDir := t.TempDir()
	tu.WriteProvisionedPKI(t, stateDir, "10.0.0.1:7000")
	keyPath := filepath.Join(cluster.PKIDir(stateDir), "node.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.LoadPKI(stateDir); err == nil {
		t.Fatal("expected LoadPKI to reject a world-readable node key")
	}
}

func TestMatchesIdentityRejectsADifferentAddress(t *testing.T) {
	stateDir := t.TempDir()
	tu.WriteProvisionedPKI(t, stateDir, "10.0.0.1:7000")
	pki, err := cluster.LoadPKI(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.MatchesIdentity("10.0.0.9:7000"); err == nil {
		t.Fatal("expected MatchesIdentity to reject a different address")
	}
}
