package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
)

func TestWriteMemberTable(t *testing.T) {
	var buf bytes.Buffer
	err := writeMemberTable(&buf, []cluster.Member{
		{Name: "node1", ID: 1, Address: "127.0.0.1:9000", Role: "voter", Leader: true},
		{Name: "node2", ID: 2, Address: "127.0.0.1:9001", Role: "voter", Leader: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "ADDRESS") {
		t.Fatalf("missing header: %q", out)
	}
	if !strings.Contains(out, "node1") || !strings.Contains(out, "127.0.0.1:9000") || !strings.Contains(out, "yes") {
		t.Fatalf("missing leader row: %q", out)
	}
	if !strings.Contains(out, "127.0.0.1:9001") {
		t.Fatalf("missing second row: %q", out)
	}
}

func TestClusterListCommand(t *testing.T) {
	dir := t.TempDir()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	node, err := cluster.Start(cluster.Options{Dir: dir, Address: addr})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer node.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := node.Open(ctx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck

	httpsCert := filepath.Join(dir, "https.crt")
	httpsKey := filepath.Join(dir, "https.key")
	if err := os.WriteFile(httpsCert, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(httpsKey, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`
key_path: %q
cert_path: %q
db_path: %q
port: 8000
encryption_backend:
  type: "none"
`, httpsKey, httpsCert, dir)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
	})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"cluster", "list", "--config", cfgPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cluster list: %v\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, addr) {
		t.Fatalf("expected address %q in output %q", addr, got)
	}
	if !strings.Contains(got, "yes") {
		t.Fatalf("expected leader in output %q", got)
	}
}

func TestClusterAddCommand(t *testing.T) {
	dir := t.TempDir()
	addr, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir,
		Address:      addr,
		Name:         "node1",
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer database.Close() //nolint:errcheck

	httpsPEM, httpsKeyPEM := mustClusterCert(t)
	httpsCert := filepath.Join(dir, "https.crt")
	httpsKey := filepath.Join(dir, "https.key")
	if err := os.WriteFile(httpsCert, httpsPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(httpsKey, httpsKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`
key_path: %q
cert_path: %q
db_path: %q
port: 8000
encryption_backend:
  type: "none"
`, httpsKey, httpsCert, dir)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
	})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"cluster", "add", "node2", "--config", cfgPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cluster add: %v\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "node2") {
		t.Fatalf("expected token output, got %q", got)
	}
	var token string
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "join token") {
			continue
		}
		token = line
	}
	if token == "" {
		t.Fatalf("empty token in %q", got)
	}
	decoded, err := cluster.DecodeJoinToken(token)
	if err != nil {
		t.Fatalf("decode token %q: %v", token, err)
	}
	if decoded.ServerName != "node2" {
		t.Fatalf("token name %q", decoded.ServerName)
	}
	if decoded.Fingerprint == "" {
		t.Fatal("token fingerprint is empty")
	}
	if len(decoded.Addresses) == 0 {
		t.Fatal("token addresses are empty")
	}
	if strings.Contains(token, "PRIVATE KEY") {
		t.Fatal("token must not contain a private key")
	}
}

func TestClusterRemoveCommand(t *testing.T) {
	certPEM, keyPEM := mustClusterCert(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	dir1 := t.TempDir()
	httpsCertPEM, _ := mustClusterCert(t)
	db1, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: dir1,
		Address:      addr1,
		Name:         "node1",
		TLSCert:      certPEM,
		TLSKey:       keyPEM,
		HTTPSCert:    httpsCertPEM,
		APIAddress:   "127.0.0.1:8443",
	})
	if err != nil {
		t.Fatalf("start node1: %v", err)
	}
	defer db1.Close() //nolint:errcheck

	orig := cluster.ExchangeJoinToken
	t.Cleanup(func() { cluster.ExchangeJoinToken = orig })
	cluster.ExchangeJoinToken = func(ctx context.Context, raw string) (cluster.JoinMaterial, error) {
		tok, err := cluster.DecodeJoinToken(raw)
		if err != nil {
			return cluster.JoinMaterial{}, err
		}
		return cluster.JoinMaterial{
			TLSCert:    certPEM,
			TLSKey:     keyPEM,
			Join:       []string{addr1},
			ServerName: tok.ServerName,
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	token, err := db1.IssueJoinToken(ctx, "node2")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	db2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		JoinToken:    token,
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer db2.Close() //nolint:errcheck

	httpsCert := filepath.Join(dir1, "https.crt")
	httpsKey := filepath.Join(dir1, "https.key")
	if err := os.WriteFile(httpsCert, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(httpsKey, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clusterCert := filepath.Join(dir1, "cluster.crt")
	clusterKey := filepath.Join(dir1, "cluster.key")
	if err := os.WriteFile(clusterCert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clusterKey, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir1, "config.yaml")
	cfg := fmt.Sprintf(`
key_path: %q
cert_path: %q
db_path: %q
port: 8000
cluster:
  tls:
    cert_path: %q
    key_path: %q
encryption_backend:
  type: "none"
`, httpsKey, httpsCert, dir1, clusterCert, clusterKey)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
	})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"cluster", "remove", "node2", "--config", cfgPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cluster remove: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "node2") {
		t.Fatalf("expected remove confirmation, got %q", out.String())
	}

	members, err := db1.ListClusterMembers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("got %d members after remove, want 1", len(members))
	}
	if members[0].Name != "node1" {
		t.Fatalf("remaining member %q", members[0].Name)
	}
}

func mustClusterCert(t *testing.T) (certPEM, keyPEM []byte) {
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
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "notary-cluster"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", "notary-cluster"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
