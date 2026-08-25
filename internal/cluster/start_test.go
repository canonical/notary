//go:build linux

package cluster_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/canonical/notary/internal/cluster"
)

const testAddress = "10.0.0.1:9000"

// writeDataDirFile puts a file into the directory dqlite owns, standing in for
// whatever a node left behind.
func writeDataDirFile(t *testing.T, stateDir, name string) {
	t.Helper()

	dir := cluster.DataDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("couldn't create the data directory: %s", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatalf("couldn't write %s: %s", name, err)
	}
}

// A node that is only asked to resume must find dqlite metadata naming the
// cluster it belongs to. Without it dqlite bootstraps, which would split the
// node off into a cluster of its own without saying so.
func TestStartRefusesWithoutCompleteMetadata(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, stateDir string)
	}{
		{"nothing at all", func(*testing.T, string) {}},
		{
			// The case that matters in practice: the PKI survived, the volume
			// holding dqlite's data did not.
			"PKI intact but no dqlite data",
			func(t *testing.T, stateDir string) {
				if _, err := cluster.EnsurePKI(stateDir, testAddress); err != nil {
					t.Fatalf("couldn't create the PKI: %s", err)
				}
			},
		},
		{
			"data directory holds only fragments",
			func(t *testing.T, stateDir string) {
				if _, err := cluster.EnsurePKI(stateDir, testAddress); err != nil {
					t.Fatalf("couldn't create the PKI: %s", err)
				}
				writeDataDirFile(t, stateDir, "dqlite-lock")
			},
		},
		{
			"identity without a peer list",
			func(t *testing.T, stateDir string) {
				if _, err := cluster.EnsurePKI(stateDir, testAddress); err != nil {
					t.Fatalf("couldn't create the PKI: %s", err)
				}
				writeDataDirFile(t, stateDir, "info.yaml")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()
			tt.setup(t, stateDir)

			node, err := cluster.Start(cluster.Options{StateDir: stateDir, Address: testAddress})
			if err == nil {
				_ = node.Close(t.Context())
				t.Fatal("expected the node to refuse to start")
			}
			if !errors.Is(err, cluster.ErrNotInitialized) {
				t.Fatalf("got %v, want ErrNotInitialized", err)
			}
		})
	}
}

// Bootstrapping and joining both build a membership from nothing, so neither may
// run over a directory that already carries a node's data.
func TestStartRefusesToFormAClusterOverExistingState(t *testing.T) {
	tests := []struct {
		name string
		opts cluster.Options
	}{
		{"bootstrap", cluster.Options{Address: testAddress, Bootstrap: true}},
		{"join", cluster.Options{Address: testAddress, Join: []string{"10.0.0.2:9000"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()
			writeDataDirFile(t, stateDir, "cluster.yaml")

			opts := tt.opts
			opts.StateDir = stateDir

			node, err := cluster.Start(opts)
			if err == nil {
				_ = node.Close(t.Context())
				t.Fatal("expected the node to refuse to start")
			}
			if !errors.Is(err, cluster.ErrAlreadyInitialized) {
				t.Fatalf("got %v, want ErrAlreadyInitialized", err)
			}
		})
	}
}
