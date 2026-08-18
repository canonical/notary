package cluster_test

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/cluster"
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

func TestEnsurePKIBootstrapsClusterCA(t *testing.T) {
	stateDir := t.TempDir()

	pki, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000")
	if err != nil {
		t.Fatalf("EnsurePKI returned an error: %v", err)
	}

	for _, name := range []string{"cluster.crt", "cluster.key", "node.crt", "node.key"} {
		if _, err := os.Stat(filepath.Join(cluster.PKIDir(stateDir), name)); err != nil {
			t.Errorf("expected PKI file %s to exist: %v", name, err)
		}
	}

	cert := nodeCertificate(t, pki)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pki.Pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("node certificate does not verify against the cluster CA: %v", err)
	}
}

// go-dqlite derives the TLS ServerName it presents to peers from the first DNS
// SAN of the node's own certificate, and panics outright if there is none
// (app.SimpleDialTLSConfig). Every node must therefore agree on that name.
func TestEnsurePKINodeCertificateCarriesSharedDNSSANFirst(t *testing.T) {
	first := nodeCertificate(t, mustEnsurePKI(t, "10.0.0.1:7000"))
	second := nodeCertificate(t, mustEnsurePKI(t, "10.0.0.2:7000"))

	if len(first.DNSNames) == 0 || len(second.DNSNames) == 0 {
		t.Fatal("node certificates must carry at least one DNS SAN")
	}
	if first.DNSNames[0] != second.DNSNames[0] {
		t.Errorf("nodes disagree on the cluster DNS SAN: %q vs %q", first.DNSNames[0], second.DNSNames[0])
	}
}

func TestEnsurePKIRecordsNodeAddress(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantIP      string
		wantDNSName string
	}{
		{name: "ip and port", address: "10.0.0.1:7000", wantIP: "10.0.0.1"},
		{name: "bare ip", address: "10.0.0.1", wantIP: "10.0.0.1"},
		{name: "hostname and port", address: "node-1.example.com:7000", wantDNSName: "node-1.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := nodeCertificate(t, mustEnsurePKI(t, tt.address))

			if tt.wantIP != "" {
				if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP(tt.wantIP)) {
					t.Errorf("expected IP SAN %s, got %v", tt.wantIP, cert.IPAddresses)
				}
			}
			if tt.wantDNSName != "" {
				if len(cert.DNSNames) != 2 || cert.DNSNames[1] != tt.wantDNSName {
					t.Errorf("expected DNS SAN %s, got %v", tt.wantDNSName, cert.DNSNames)
				}
			}
			if cert.Subject.CommonName != tt.address {
				t.Errorf("expected common name %q, got %q", tt.address, cert.Subject.CommonName)
			}
		})
	}
}

func TestEnsurePKIReusesExistingMaterial(t *testing.T) {
	stateDir := t.TempDir()

	first, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000")
	if err != nil {
		t.Fatalf("EnsurePKI returned an error: %v", err)
	}
	second, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000")
	if err != nil {
		t.Fatalf("EnsurePKI returned an error on reload: %v", err)
	}

	if nodeCertificate(t, first).SerialNumber.Cmp(nodeCertificate(t, second).SerialNumber) != 0 {
		t.Error("EnsurePKI regenerated the node certificate instead of loading the existing one")
	}
}

func TestEnsurePKIKeysAreNotWorldReadable(t *testing.T) {
	stateDir := t.TempDir()

	if _, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000"); err != nil {
		t.Fatalf("EnsurePKI returned an error: %v", err)
	}

	for _, name := range []string{"cluster.key", "node.key"} {
		info, err := os.Stat(filepath.Join(cluster.PKIDir(stateDir), name))
		if err != nil {
			t.Fatalf("failed to stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("expected %s to be mode 0600, got %#o", name, perm)
		}
	}
}

func TestEnsurePKIClusterCAIsACA(t *testing.T) {
	stateDir := t.TempDir()

	if _, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000"); err != nil {
		t.Fatalf("EnsurePKI returned an error: %v", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(cluster.PKIDir(stateDir), "cluster.crt"))
	if err != nil {
		t.Fatalf("failed to read cluster CA: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("cluster CA is not valid PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cluster CA: %v", err)
	}

	if !caCert.IsCA {
		t.Error("expected the cluster CA certificate to be a CA")
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected the cluster CA to be allowed to sign certificates")
	}
}

func TestEnsurePKIRejectsCorruptClusterCA(t *testing.T) {
	stateDir := t.TempDir()

	if err := os.MkdirAll(cluster.PKIDir(stateDir), 0o700); err != nil {
		t.Fatalf("failed to create PKI directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cluster.PKIDir(stateDir), "cluster.crt"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("failed to write corrupt CA: %v", err)
	}

	if _, err := cluster.EnsurePKI(stateDir, "10.0.0.1:7000"); err == nil {
		t.Error("expected EnsurePKI to reject a corrupt cluster CA")
	}
}

func mustEnsurePKI(t *testing.T, address string) *cluster.PKI {
	t.Helper()

	pki, err := cluster.EnsurePKI(t.TempDir(), address)
	if err != nil {
		t.Fatalf("EnsurePKI returned an error: %v", err)
	}

	return pki
}
