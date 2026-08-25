package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/db"
	"go.uber.org/zap"
)

// flakyBackend stands in for Vault or an HSM that is unreachable when the node
// starts and comes back later.
type flakyBackend struct {
	mu        sync.Mutex
	reachable bool
}

var errBackendUnreachable = errors.New("encryption backend is unreachable")

func (b *flakyBackend) recover() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reachable = true
}

func (b *flakyBackend) up() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reachable
}

func (b *flakyBackend) Encrypt(plaintext []byte) ([]byte, error) {
	if !b.up() {
		return nil, errBackendUnreachable
	}
	return plaintext, nil
}

func (b *flakyBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	if !b.up() {
		return nil, errBackendUnreachable
	}
	return ciphertext, nil
}

func mustOpenDatabase(t *testing.T) *db.DatabaseRepository {
	t.Helper()

	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath:    filepath.Join(t.TempDir(), "notary.db"),
		ApplyMigrations: true,
		Logger:          zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("couldn't open the database: %s", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	return database
}

func caKeyPath(stateDir string) string {
	return filepath.Join(cluster.PKIDir(stateDir), "cluster.key")
}

// A node that bootstraps while its encryption backend is down must still end up
// with the cluster CA key replicated, without an operator restarting it. The key
// is encrypted with the data encryption key, so it cannot be stored until the
// unwrap succeeds, and the unwrap is what the backend being down prevents.
func TestClusterCAKeyIsStoredOnceTheBackendRecovers(t *testing.T) {
	const nodeAddress = "10.0.0.1:9000"

	stateDir := t.TempDir()
	if _, err := cluster.EnsurePKI(stateDir, nodeAddress); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}
	diskKey, err := cluster.LoadCAKey(stateDir)
	if err != nil {
		t.Fatalf("couldn't read the bootstrapped CA key: %s", err)
	}

	database := mustOpenDatabase(t)
	backend := &flakyBackend{}
	clusterCfg := ClusterConfig{Enabled: true, StateDir: stateDir, Address: nodeAddress}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := startUnsealing(ctx, database, clusterCfg, backend, zap.NewNop(), time.Millisecond)

	// While the backend is unreachable the node stays sealed, and the key it
	// cannot yet encrypt is left exactly where it is.
	if !state.Sealed() {
		t.Fatal("the node reported itself unsealed with the backend down")
	}
	if _, err := os.Stat(caKeyPath(stateDir)); err != nil {
		t.Errorf("the CA key was removed from disk before it was stored: %s", err)
	}
	if _, err := database.GetClusterCAKey(); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("expected no stored CA key while sealed, got %v", err)
	}

	backend.recover()

	deadline := time.Now().Add(10 * time.Second)
	for state.Sealed() {
		if time.Now().After(deadline) {
			t.Fatalf("the node did not unseal after the backend recovered: %v", state.LastError())
		}
		time.Sleep(2 * time.Millisecond)
	}

	stored, err := database.GetClusterCAKey()
	if err != nil {
		t.Fatalf("the CA key was not stored after the backend recovered: %s", err)
	}
	if !bytes.Equal(stored, diskKey) {
		t.Error("the stored CA key is not the one this node bootstrapped with")
	}

	// Only removed once the replicated copy read back, which it now has.
	if _, err := os.Stat(caKeyPath(stateDir)); !os.IsNotExist(err) {
		t.Error("the plaintext CA key is still on disk after being stored")
	}

	// The point of all of it: this node can admit a member again.
	joinerDir := t.TempDir()
	csrPEM, err := cluster.PrepareJoin(joinerDir, "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("couldn't prepare a join: %s", err)
	}
	certPEM, caCertPEM, err := cluster.SignJoinRequest(stateDir, stored, csrPEM, "10.0.0.2:9000")
	if err != nil {
		t.Fatalf("the recovered CA key could not sign a join request: %s", err)
	}
	if err := cluster.CompleteJoin(joinerDir, certPEM, caCertPEM); err != nil {
		t.Fatalf("the certificate it issued is unusable: %s", err)
	}
}

// A key that cannot be read is not the same as one that was never there, and
// must not let the node come up looking healthy.
func TestUnsealFailsWhenTheCAKeyIsUnreadable(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := cluster.EnsurePKI(stateDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}
	if err := os.WriteFile(caKeyPath(stateDir), []byte("not a key"), 0o600); err != nil {
		t.Fatalf("couldn't corrupt the CA key: %s", err)
	}

	database := mustOpenDatabase(t)
	backend := &flakyBackend{reachable: true}
	clusterCfg := ClusterConfig{Enabled: true, StateDir: stateDir, Address: "10.0.0.1:9000"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := startUnsealing(ctx, database, clusterCfg, backend, zap.NewNop(), time.Millisecond)

	if !state.Sealed() {
		t.Fatal("the node unsealed with an unreadable cluster CA key")
	}
	if state.LastError() == nil {
		t.Error("no failure was recorded for the unreadable cluster CA key")
	}
}

// A member that joined has no key on disk and must not be held back by that: it
// receives the row through replication.
func TestUnsealSucceedsForAMemberWithNoCAKeyOnDisk(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := cluster.EnsurePKI(stateDir, "10.0.0.1:9000"); err != nil {
		t.Fatalf("couldn't bootstrap the cluster PKI: %s", err)
	}
	if err := cluster.RemoveCAKey(stateDir); err != nil {
		t.Fatalf("couldn't remove the CA key: %s", err)
	}

	database := mustOpenDatabase(t)
	backend := &flakyBackend{reachable: true}
	clusterCfg := ClusterConfig{Enabled: true, StateDir: stateDir, Address: "10.0.0.1:9000"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state := startUnsealing(ctx, database, clusterCfg, backend, zap.NewNop(), time.Millisecond)

	if state.Sealed() {
		t.Fatalf("a joined member stayed sealed: %v", state.LastError())
	}
}
