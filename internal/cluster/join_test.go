package cluster_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

func TestExchangeJoinTokenPinsFingerprint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cluster/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"server_name":         "node2",
				"cluster_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
				"cluster_private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
				"addresses":           []string{"127.0.0.1:9000"},
			},
		})
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	sum := sha256.Sum256(ts.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	addr := strings.TrimPrefix(ts.URL, "https://")

	raw, err := encodeTestToken("node2", fp, addr)
	if err != nil {
		t.Fatal(err)
	}
	material, err := cluster.ExchangeJoinTokenHTTPS(context.Background(), raw)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if material.ServerName != "node2" || len(material.Join) != 1 {
		t.Fatalf("%+v", material)
	}

	rawBad, err := encodeTestToken("node2", "00"+fp[2:], addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.ExchangeJoinTokenHTTPS(context.Background(), rawBad); err == nil {
		t.Fatal("expected fingerprint mismatch")
	}
}

func TestJoinAPIAddressRejectsUnspecified(t *testing.T) {
	if _, err := cluster.JoinAPIAddress("0.0.0.0:9000", 8000, ""); err == nil {
		t.Fatal("expected error for 0.0.0.0")
	}
	if _, err := cluster.JoinAPIAddress("[::]:9000", 8000, ""); err == nil {
		t.Fatal("expected error for ::")
	}
	if _, err := cluster.JoinAPIAddress("0.0.0.0:9000", 8000, "localhost"); err == nil {
		t.Fatal("expected error for wildcard bind with localhost")
	}
	if _, err := cluster.JoinAPIAddress("0.0.0.0:9000", 8000, "127.0.0.1"); err == nil {
		t.Fatal("expected error for wildcard bind with loopback")
	}
	got, err := cluster.JoinAPIAddress("0.0.0.0:9000", 8000, "notary.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "notary.example.com:8000" {
		t.Fatalf("got %q", got)
	}
	got, err = cluster.JoinAPIAddress("10.0.0.1:9000", 3000, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.1:3000" {
		t.Fatalf("got %q", got)
	}
	got, err = cluster.JoinAPIAddress("10.0.0.1:9000", 3000, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.1:3000" {
		t.Fatalf("default localhost must not override a routable bind, got %q", got)
	}
	got, err = cluster.JoinAPIAddress("127.0.0.1:9000", 8000, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if got != "localhost:8000" {
		t.Fatalf("got %q", got)
	}
}

func encodeTestToken(name, fingerprint, addr string) (string, error) {
	body, err := json.Marshal(cluster.JoinToken{
		ServerName:  name,
		Fingerprint: fingerprint,
		Addresses:   []string{addr},
		Secret:      "secret",
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(body), nil
}
