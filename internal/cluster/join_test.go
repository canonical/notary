package cluster_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestExchangeJoinTokenCAOmitsKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cluster/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"server_name": "node2",
				"addresses":   []string{"127.0.0.1:9000"},
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
	if len(material.TLSKey) != 0 || len(material.TLSCert) != 0 {
		t.Fatalf("CA redeem must not include a private key: %+v", material)
	}
	if material.ServerName != "node2" || len(material.Join) != 1 {
		t.Fatalf("%+v", material)
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

func TestJoinAPIAddressesIncludeFallback(t *testing.T) {
	cases := []struct {
		name     string
		cluster  string
		port     int
		hostname string
		want     []string
		wantErr  bool
	}{
		{"hostname plus routable fallback", "10.0.0.1:9000", 3000, "notary.example.com", []string{"notary.example.com:3000", "10.0.0.1:3000"}, false},
		{"no hostname gives bind address only", "10.0.0.1:9000", 3000, "", []string{"10.0.0.1:3000"}, false},
		{"default localhost must not override routable bind", "10.0.0.1:9000", 3000, "localhost", []string{"10.0.0.1:3000"}, false},
		{"loopback bind keeps hostname first", "127.0.0.1:9000", 8000, "localhost", []string{"localhost:8000", "127.0.0.1:8000"}, false},
		{"wildcard bind drops fallback", "0.0.0.0:9000", 8000, "notary.example.com", []string{"notary.example.com:8000"}, false},
		{"hostname port preserved", "10.0.0.1:9000", 3000, "notary.example.com:8443", []string{"notary.example.com:8443", "10.0.0.1:3000"}, false},
		{"wildcard without hostname errors", "0.0.0.0:9000", 8000, "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cluster.JoinAPIAddresses(tc.cluster, tc.port, tc.hostname)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExchangeJoinTokenFallsBackToSecondAddress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cluster/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"server_name": "node2",
				"addresses":   []string{"127.0.0.1:9000"},
			},
		})
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	sum := sha256.Sum256(ts.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	live := strings.TrimPrefix(ts.URL, "https://")

	// A closed port refuses connections immediately.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := encodeTestTokenAddrs("node2", fp, []string{dead, live})
	if err != nil {
		t.Fatal(err)
	}
	material, err := cluster.ExchangeJoinTokenHTTPS(context.Background(), raw)
	if err != nil {
		t.Fatalf("exchange should fall back to the second address: %v", err)
	}
	if material.ServerName != "node2" {
		t.Fatalf("%+v", material)
	}

	// All addresses dead: the error must surface.
	rawDead, err := encodeTestTokenAddrs("node2", fp, []string{dead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.ExchangeJoinTokenHTTPS(context.Background(), rawDead); err == nil {
		t.Fatal("expected error when every address is unreachable")
	}
}

func TestExchangeJoinTokenFallsBackWhenPrimaryStalls(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/cluster/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"server_name": "node2",
				"addresses":   []string{"127.0.0.1:9000"},
			},
		})
	})
	live := httptest.NewTLSServer(mux)
	t.Cleanup(live.Close)

	// The primary accepts TCP and completes TLS but never writes an HTTP
	// response. A raw listener (no handler goroutine) avoids a leaked server
	// goroutine blocking test teardown.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stallLn.Close() })
	stallAddr := stallLn.Addr().String()
	go func() {
		for {
			conn, err := stallLn.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without answering; close on test end.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	// The token pins the live server's certificate so the fallback succeeds;
	// the staller never gets far enough to present one.
	liveSum := sha256.Sum256(live.Certificate().Raw)
	liveFP := hex.EncodeToString(liveSum[:])
	raw, err := encodeTestTokenAddrs("node2", liveFP, []string{
		stallAddr,
		strings.TrimPrefix(live.URL, "https://"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A shared 12s deadline: without a per-address budget the stalled primary
	// (capped only by the client's 15s Timeout) would expire it before the
	// fallback is tried. With the 5s budget the exchange must return promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	start := time.Now()
	material, err := cluster.ExchangeJoinTokenHTTPS(ctx, raw)
	elapsed := time.Since(start)
	if elapsed > 8*time.Second {
		t.Fatalf("stalled primary consumed %v, want the 5s per-address budget", elapsed)
	}
	if err != nil {
		t.Fatalf("fallback to the live address must succeed after the stall: %v", err)
	}
	if material.ServerName != "node2" {
		t.Fatalf("%+v", material)
	}
}

func TestProbeJoinAddress(t *testing.T) {
	ts := httptest.NewTLSServer(http.NewServeMux())
	t.Cleanup(ts.Close)
	live := strings.TrimPrefix(ts.URL, "https://")
	if err := cluster.ProbeJoinAddress(context.Background(), live); err != nil {
		t.Fatalf("live address: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cluster.ProbeJoinAddress(context.Background(), dead); err == nil {
		t.Fatal("expected dial error for closed port")
	}
	if err := cluster.ProbeJoinAddress(context.Background(), "not-a-host.invalid:8443"); err == nil {
		t.Fatal("expected resolve error for bogus hostname")
	}
}

func encodeTestToken(name, fingerprint, addr string) (string, error) {
	return encodeTestTokenAddrs(name, fingerprint, []string{addr})
}

func encodeTestTokenAddrs(name, fingerprint string, addrs []string) (string, error) {
	body, err := json.Marshal(cluster.JoinToken{
		ServerName:  name,
		Fingerprint: fingerprint,
		Addresses:   addrs,
		Secret:      "secret",
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(body), nil
}
