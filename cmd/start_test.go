package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
)

func TestStartSIGTERM(t *testing.T) {
	if configPath := os.Getenv("NOTARY_TEST_START_CONFIG"); configPath != "" {
		rootCmd.SetArgs([]string{"start", "--config", configPath})
		if err := rootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	certPEM, keyPEM := mustClusterCert(t)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	configPath := filepath.Join(dir, "config.yaml")
	apiAddress, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(apiAddress)
	if err != nil {
		t.Fatal(err)
	}
	clusterAddress, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("key_path: %q\ncert_path: %q\ndb_path: %q\nport: %s\ncluster:\n  address: %q\nencryption_backend:\n  type: none\n",
		keyPath, certPath, filepath.Join(dir, "db"), port, clusterAddress)
	for path, contents := range map[string][]byte{certPath: certPEM, keyPath: keyPEM, configPath: []byte(config)} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartSIGTERM$")
	process.Env = append(os.Environ(), "NOTARY_TEST_START_CONFIG="+configPath)
	var output bytes.Buffer
	process.Stdout = &output
	process.Stderr = &output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			cancel()
			_ = process.Wait()
		}
	})
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get("https://" + apiAddress + "/status")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			_ = process.Wait()
			waited = true
			t.Fatalf("server did not become ready: %s", output.String())
		case <-ticker.C:
		}
	}
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = process.Wait()
	waited = true
	if err != nil {
		t.Fatalf("SIGTERM did not exit cleanly: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "Shutting down server") {
		t.Fatalf("missing graceful shutdown log: %s", output.String())
	}
}
