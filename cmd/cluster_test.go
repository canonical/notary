package cmd

import (
	"bytes"
	"context"
	"fmt"
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
}
