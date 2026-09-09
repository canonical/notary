package cluster_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
)

func TestCAModeTwoNodesShareData(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	leaf1Cert, leaf1Key := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	leaf2Cert, leaf2Key := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})

	dir1 := t.TempDir()
	node1, err := cluster.Start(cluster.Options{
		Dir:     dir1,
		Address: addr1,
		TLS: cluster.CAPeer{
			CA: caPEM, Cert: leaf1Cert, Key: leaf1Key, PeerSAN: cluster.DefaultPeerSAN,
		},
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer node1.Close() //nolint:errcheck

	if _, err := os.Stat(filepath.Join(dir1, "cluster.key")); err == nil {
		t.Fatal("CA mode must not persist db_path/cluster.key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db1, err := node1.Open(ctx)
	if err != nil {
		t.Fatalf("open node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck
	if _, err := db1.ExecContext(ctx, `CREATE TABLE t (id INTEGER PRIMARY KEY, n TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db1.ExecContext(ctx, `INSERT INTO t (id, n) VALUES (1, 'ok')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	node2, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr2,
		Join:    []string{addr1},
		TLS: cluster.CAPeer{
			CA: caPEM, Cert: leaf2Cert, Key: leaf2Key, PeerSAN: cluster.DefaultPeerSAN,
		},
	})
	if err != nil {
		t.Fatalf("start node2: %v", err)
	}
	defer node2.Close() //nolint:errcheck

	db2, err := node2.Open(ctx)
	if err != nil {
		t.Fatalf("open node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	var n string
	if err := db2.QueryRowContext(ctx, `SELECT n FROM t WHERE id = 1`).Scan(&n); err != nil {
		t.Fatalf("read from joiner: %v", err)
	}
	if n != "ok" {
		t.Fatalf("got %q", n)
	}
}

func TestCAModeResumeDoesNotGenerateSharedPair(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	dir := t.TempDir()
	tls := cluster.CAPeer{CA: caPEM, Cert: leafCert, Key: leafKey, PeerSAN: cluster.DefaultPeerSAN}
	n1, err := cluster.Start(cluster.Options{Dir: dir, Address: addr, TLS: tls})
	if err != nil {
		t.Fatal(err)
	}
	if err := n1.Close(); err != nil {
		t.Fatal(err)
	}
	n2, err := cluster.Start(cluster.Options{Dir: dir, Address: addr, TLS: tls})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer n2.Close() //nolint:errcheck
	if _, err := os.Stat(filepath.Join(dir, "cluster.key")); err == nil {
		t.Fatal("CA resume must not write cluster.key")
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster.crt")); err == nil {
		t.Fatal("CA resume must not write cluster.crt")
	}
}

func TestSharedClusterRejectsCAJoiner(t *testing.T) {
	certPEM, keyPEM := mustClusterCert(t)
	caPEM, caKey := mustTestCA(t)
	leafCert, leafKey := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	node1, err := cluster.Start(cluster.Options{
		Dir: t.TempDir(), Address: addr1, TLSCert: certPEM, TLSKey: keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node1.Close() //nolint:errcheck

	_, err = cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr2,
		Join:    []string{addr1},
		TLS: cluster.CAPeer{
			CA: caPEM, Cert: leafCert, Key: leafKey, PeerSAN: cluster.DefaultPeerSAN,
		},
	})
	if err == nil {
		t.Fatal("CA joiner must not join a shared-pair cluster")
	}
}

func TestCAClusterRejectsSharedJoiner(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	leafCert, leafKey := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	sharedCert, sharedKey := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	node1, err := cluster.Start(cluster.Options{
		Dir:     t.TempDir(),
		Address: addr1,
		TLS: cluster.CAPeer{
			CA: caPEM, Cert: leafCert, Key: leafKey, PeerSAN: cluster.DefaultPeerSAN,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node1.Close() //nolint:errcheck

	_, err = cluster.Start(cluster.Options{
		Dir: t.TempDir(), Address: addr2, Join: []string{addr1}, TLSCert: sharedCert, TLSKey: sharedKey,
	})
	if err == nil {
		t.Fatal("shared-pair joiner must not join a CA-mode cluster")
	}
}

func TestCAJoinRejectsRedeemedPrivateKey(t *testing.T) {
	caPEM, caKey := mustTestCA(t)
	leafCert, leafKey := mustCALeaf(t, caPEM, caKey, []string{cluster.DefaultPeerSAN}, []net.IP{net.ParseIP("127.0.0.1")})
	sharedCert, sharedKey := mustClusterCert(t)
	orig := cluster.ExchangeJoinToken
	t.Cleanup(func() { cluster.ExchangeJoinToken = orig })
	cluster.ExchangeJoinToken = func(context.Context, string) (cluster.JoinMaterial, error) {
		return cluster.JoinMaterial{
			TLSCert:    sharedCert,
			TLSKey:     sharedKey,
			Join:       []string{"127.0.0.1:1"},
			ServerName: "node2",
		}, nil
	}
	raw, err := encodeTestToken("node2", "deadbeef", "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cluster.Start(cluster.Options{
		Dir:       t.TempDir(),
		Address:   "127.0.0.1:1",
		JoinToken: raw,
		TLS: cluster.CAPeer{
			CA: caPEM, Cert: leafCert, Key: leafKey, PeerSAN: cluster.DefaultPeerSAN,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "CA mode") {
		t.Fatalf("got %v", err)
	}
}

func mustTestCA(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "notary-cluster-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func mustCALeaf(t *testing.T, caPEM []byte, caKey *rsa.PrivateKey, dns []string, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "notary-unit"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
