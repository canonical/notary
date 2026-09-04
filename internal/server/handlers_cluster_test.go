package server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internallog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	tu "github.com/canonical/notary/internal/testutils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestListClusterMembers(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	req, err := http.NewRequest("GET", ts.URL+"/api/v1/cluster", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", res.StatusCode, http.StatusOK)
	}

	var body struct {
		Data []struct {
			Name    string `json:"name"`
			ID      uint64 `json:"id"`
			Address string `json:"address"`
			Role    string `json:"role"`
			Leader  bool   `json:"leader"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data) != 1 {
		t.Fatalf("got %d members, want 1", len(body.Data))
	}
	m := body.Data[0]
	if m.ID == 0 {
		t.Fatal("expected member id")
	}
	if !strings.HasPrefix(m.Address, "127.0.0.1:") {
		t.Fatalf("unexpected address %q", m.Address)
	}
	if m.Role == "" {
		t.Fatal("expected role")
	}
	if m.Name == "" {
		t.Fatal("expected member name")
	}
	if !m.Leader {
		t.Fatal("expected single-node member to be leader")
	}
}

func TestAddClusterMemberToken(t *testing.T) {
	ts, _ := tu.MustPrepareServer(t)
	client := ts.Client()
	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/cluster/members", strings.NewReader(`{"server_name":"node2"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("got %d, want %d", res.StatusCode, http.StatusCreated)
	}
	var body struct {
		Data struct {
			ServerName string `json:"server_name"`
			JoinToken  string `json:"join_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.ServerName != "node2" || body.Data.JoinToken == "" {
		t.Fatalf("unexpected data %+v", body.Data)
	}
	if strings.Contains(body.Data.JoinToken, "PRIVATE KEY") {
		t.Fatal("token must not contain a private key")
	}

	del, err := http.NewRequest("DELETE", ts.URL+"/api/v1/cluster/members/"+body.Data.ServerName, nil)
	if err != nil {
		t.Fatal(err)
	}
	del.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	delRes, err := client.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer delRes.Body.Close()
	if delRes.StatusCode != http.StatusNotFound && delRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("remove pending name: got %d", delRes.StatusCode)
	}
}

func TestDeleteLiveJoinedMember(t *testing.T) {
	certPEM, keyPEM := mustClusterTLS(t)
	addr1, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := cluster.FreeAddress()
	if err != nil {
		t.Fatal(err)
	}

	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr1,
		Name:         "node1",
		TLSCert:      certPEM,
		TLSKey:       keyPEM,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("NewDatabase: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	core, _ := observer.New(zapcore.InfoLevel)
	appCfg := tu.MustCreateTestAppConfig(t)
	appEnv := tu.MustCreateTestAppEnvironment(t, database)
	appEnv.AuditLogger = internallog.NewAuditLogger(zap.New(core))
	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv.Handler)
	t.Cleanup(ts.Close)

	adminToken := tu.MustPrepareAccount(t, ts, "admin@canonical.com", tu.RoleAdmin, "")

	node2, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath: t.TempDir(),
		Address:      addr2,
		Name:         "node2",
		Join:         []string{addr1},
		TLSCert:      certPEM,
		TLSKey:       keyPEM,
		Logger:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("join node2: %v", err)
	}
	defer node2.Close() //nolint:errcheck

	del, err := http.NewRequest("DELETE", ts.URL+"/api/v1/cluster/members/node2", nil)
	if err != nil {
		t.Fatal(err)
	}
	del.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	delRes, err := ts.Client().Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer delRes.Body.Close() //nolint:errcheck
	if delRes.StatusCode != http.StatusAccepted {
		t.Fatalf("DELETE live member: got %d, want %d", delRes.StatusCode, http.StatusAccepted)
	}

	req, err := http.NewRequest("GET", ts.URL+"/api/v1/cluster", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:     server.CookieSessionTokenKey,
		Value:    adminToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	var body struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].Name != "node1" {
		t.Fatalf("after delete: %+v", body.Data)
	}
}

func mustClusterTLS(t *testing.T) (certPEM, keyPEM []byte) {
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
