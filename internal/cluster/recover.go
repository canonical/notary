package cluster

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	dqlite "github.com/canonical/go-dqlite/v3"
	"github.com/canonical/go-dqlite/v3/client"
	"gopkg.in/yaml.v2"
)

// LastEntry describes the last raft log entry in a data directory. Compare it
// across surviving members to find the most up-to-date one before recovering.
type LastEntry struct {
	Term  uint64
	Index uint64
}

// Before reports whether e is strictly less recent than other.
func (e LastEntry) Before(other LastEntry) bool {
	return e.Term < other.Term || (e.Term == other.Term && e.Index < other.Index)
}

func (e LastEntry) String() string {
	return fmt.Sprintf("term %d, index %d", e.Term, e.Index)
}

// ReadLastEntry reports the last raft entry in dir. The node must not be
// running. This renames open raft segments to closed ones, so it is not
// read-only even though it does not discard data.
func ReadLastEntry(dir string) (LastEntry, error) {
	if !HasState(dir) {
		return LastEntry{}, fmt.Errorf("%s is not a Notary cluster data directory", dir)
	}
	info, err := dqlite.ReadLastEntryInfo(dir)
	if err != nil {
		return LastEntry{}, fmt.Errorf("read raft log in %s: %w", dir, err)
	}
	return LastEntry{Term: info.Term, Index: info.Index}, nil
}

// LocalNodeInfo reads this node's dqlite identity from info.yaml.
func LocalNodeInfo(dir string) (client.NodeInfo, error) {
	var info client.NodeInfo
	body, err := os.ReadFile(filepath.Join(dir, infoFile)) // #nosec G304 -- dir is db_path from config
	if err != nil {
		return info, fmt.Errorf("read %s: %w", infoFile, err)
	}
	if err := yaml.Unmarshal(body, &info); err != nil {
		return info, fmt.Errorf("parse %s: %w", infoFile, err)
	}
	if info.Address == "" {
		return info, fmt.Errorf("%s has no address", infoFile)
	}
	return info, nil
}

// RecoverToSelf forces dir into a single-voter cluster containing only this
// node, so a survivor of quorum loss becomes writable again. Every node must be
// stopped. This is destructive: entries the lost majority had committed but
// never replicated here are discarded.
func RecoverToSelf(dir string) (client.NodeInfo, error) {
	info, err := LocalNodeInfo(dir)
	if err != nil {
		return info, err
	}
	info.Role = client.Voter
	if err := dqlite.ReconfigureMembershipExt(dir, []dqlite.NodeInfo{info}); err != nil {
		return info, fmt.Errorf("recover cluster in %s: %w", dir, err)
	}
	if err := writeRecoveredStore(dir, info); err != nil {
		return info, err
	}
	return info, nil
}

// writeRecoveredStore replaces cluster.yaml so clients stop dialling members
// that are no longer part of the cluster.
func writeRecoveredStore(dir string, info client.NodeInfo) error {
	store, err := client.NewYamlNodeStore(filepath.Join(dir, storeFile))
	if err != nil {
		return fmt.Errorf("open cluster membership: %w", err)
	}
	if err := store.Set(context.Background(), []client.NodeInfo{info}); err != nil {
		return fmt.Errorf("write cluster membership: %w", err)
	}
	return nil
}
