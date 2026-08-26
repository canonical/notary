package testutils

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/canonical/notary/internal/backends/encryption"
	internalLog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// FakeClusterNode stands in for a real dqlite node so the cluster HTTP API can
// be exercised without one. It reports whatever membership the test sets, and
// records the calls a handler makes so the test can assert they happened.
type FakeClusterNode struct {
	NodeID      uint64
	NodeAddress string
	MemberList  []cluster.MemberInfo
	LeaderID    uint64
	// Err, when set, is returned by every membership query, which is what a
	// handler sees when the cluster is unreachable.
	Err      error
	mu       sync.Mutex
	promoted []uint64
}

func (n *FakeClusterNode) Open(ctx context.Context, name string) (*sql.DB, error) {
	return nil, errors.New("not implemented")
}

func (n *FakeClusterNode) Ready(ctx context.Context) error { return nil }

func (n *FakeClusterNode) ID() uint64 { return n.NodeID }

func (n *FakeClusterNode) Address() string { return n.NodeAddress }

func (n *FakeClusterNode) Members(ctx context.Context) ([]cluster.MemberInfo, error) {
	if n.Err != nil {
		return nil, n.Err
	}
	return n.MemberList, nil
}

func (n *FakeClusterNode) Leader(ctx context.Context) (*cluster.MemberInfo, error) {
	if n.Err != nil {
		return nil, n.Err
	}
	for _, member := range n.MemberList {
		if member.ID == n.LeaderID {
			return &member, nil
		}
	}
	return nil, nil
}

func (n *FakeClusterNode) Promote(ctx context.Context, id uint64) error {
	if n.Err != nil {
		return n.Err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.promoted = append(n.promoted, id)
	return nil
}

func (n *FakeClusterNode) Close(ctx context.Context) error { return nil }

// Promoted returns the node IDs Promote was called with, in order.
func (n *FakeClusterNode) Promoted() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.promoted...)
}

// MustPrepareClusterServer starts a test server with the cluster API enabled,
// backed by node and by a freshly bootstrapped cluster PKI, and returns it
// alongside the server's state directory.
func MustPrepareClusterServer(t *testing.T, node cluster.Node) (*httptest.Server, string) {
	t.Helper()

	testServer, stateDir, _, _ := mustPrepareClusterServer(t, node, false)
	return testServer, stateDir
}

// MustPrepareClusterServerWithDatabase is MustPrepareClusterServer with the
// repository handed back as well, so a test can take storage away from a running
// server. That is what a node experiences when the cluster loses quorum: the
// process is still up and still serving, but every query it issues fails.
func MustPrepareClusterServerWithDatabase(t *testing.T, node cluster.Node) (*httptest.Server, *db.DatabaseRepository) {
	t.Helper()

	testServer, _, _, database := mustPrepareClusterServer(t, node, false)
	return testServer, database
}

// MustPrepareSealedClusterServer is MustPrepareClusterServer with the node still
// sealed, as it is between starting and finishing its own key unwrap. The
// returned seal state lets the test unseal the node, which is what the
// configured Vault/HSM backend becoming reachable does in production.
func MustPrepareSealedClusterServer(t *testing.T, node cluster.Node) (*httptest.Server, *encryption.SealState) {
	t.Helper()

	testServer, _, sealState, _ := mustPrepareClusterServer(t, node, true)
	return testServer, sealState
}

func mustPrepareClusterServer(t *testing.T, node cluster.Node, sealed bool) (*httptest.Server, string, *encryption.SealState, *db.DatabaseRepository) {
	t.Helper()

	stateDir := t.TempDir()
	if _, err := cluster.EnsurePKI(stateDir, "127.0.0.1:9000"); err != nil {
		t.Fatalf("Couldn't bootstrap the cluster PKI: %s", err)
	}

	database := MustPrepareEmptyDB(t)

	// Signing a join reads the CA key from the database, as a bootstrapped node
	// puts it there.
	caKeyPEM, err := cluster.LoadCAKey(stateDir)
	if err != nil {
		t.Fatalf("Couldn't read the cluster CA key: %s", err)
	}
	if err := database.CreateClusterCAKey(caKeyPEM); err != nil {
		t.Fatalf("Couldn't store the cluster CA key: %s", err)
	}

	core, _ := observer.New(zapcore.InfoLevel)

	appCfg := MustCreateTestAppConfig(t)
	appCfg.ClusterConfig.Enabled = true
	appCfg.ClusterConfig.StateDir = stateDir

	appEnv := MustCreateTestAppEnvironment(t, database)
	appEnv.AuditLogger = internalLog.NewAuditLogger(zap.New(core))
	appEnv.ClusterNode = node
	if sealed {
		appEnv.EncryptionRepository.SealState = encryption.NewSealState()
	}

	srv, err := server.New(appCfg, appEnv)
	if err != nil {
		t.Fatalf("Couldn't get server: %s", err)
	}
	testServer := httptest.NewTLSServer(srv.Handler)
	t.Cleanup(testServer.Close)

	return testServer, stateDir, appEnv.EncryptionRepository.SealState, database
}

// DoClusterAPIRequest performs an authenticated request against the cluster API
// and decodes the response body into out when one is given.
func DoClusterAPIRequest(t *testing.T, ts *httptest.Server, method, path, token string, body []byte) (int, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("Couldn't build request: %s", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.AddCookie(&http.Cookie{
			Name:     server.CookieSessionTokenKey,
			Value:    token,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
	}

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Couldn't perform request: %s", err)
	}
	defer res.Body.Close() // nolint: errcheck

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Couldn't read response body: %s", err)
	}
	return res.StatusCode, responseBody
}
