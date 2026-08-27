package testutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
)

const clusterSANDNS = "notary-cluster"

// WriteProvisionedPKI writes an operator-style cluster CA and node certificate
// into stateDir, the way a charm or admin would before bootstrap or join.
func WriteProvisionedPKI(t *testing.T, stateDir, address string) {
	t.Helper()

	dir := cluster.PKIDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("couldn't create PKI directory: %s", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate CA key: %s", err)
	}
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate node key: %s", err)
	}

	now := time.Now()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	nodeSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Notary Cluster CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("couldn't create CA certificate: %s", err)
	}

	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	nodeTemplate := &x509.Certificate{
		SerialNumber: nodeSerial,
		Subject:      pkix.Name{CommonName: address},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{clusterSANDNS},
	}
	if ip := net.ParseIP(host); ip != nil {
		nodeTemplate.IPAddresses = []net.IP{ip}
	} else if host != "" {
		nodeTemplate.DNSNames = append(nodeTemplate.DNSNames, host)
	}

	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTemplate, caTemplate, &nodeKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("couldn't create node certificate: %s", err)
	}

	writePEM := func(name, pemType string, der []byte, perm os.FileMode) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), perm); err != nil {
			t.Fatalf("couldn't write %s: %s", name, err)
		}
	}

	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}

	writePEM("cluster.crt", "CERTIFICATE", caDER, 0o644)
	writePEM("node.crt", "CERTIFICATE", nodeDER, 0o644)
	if err := os.WriteFile(filepath.Join(dir, "node.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
