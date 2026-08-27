// Package cluster owns Notary's dqlite cluster node: its lifecycle, its
// cluster-internal PKI, and the replicated database handle it hands to
// internal/db.
//
// The cluster-internal PKI is entirely separate from the certificates Notary
// manages as a product. Nothing in this package is ever exposed through the
// certificate API.
package cluster

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
)

// DatabaseName is the name of the replicated database holding Notary's data.
const DatabaseName = "notary"

// dqliteDirName is the subdirectory of a node's state directory that is handed
// to dqlite. The cluster PKI deliberately lives outside it, so dqlite owns its
// data directory exclusively.
const dqliteDirName = "database"

// DataDir returns the directory dqlite owns for a node whose state lives in
// stateDir.
func DataDir(stateDir string) string {
	return filepath.Join(stateDir, dqliteDirName)
}

// ErrUnsupportedPlatform is returned by Start on platforms where dqlite is
// unavailable. libdqlite requires Linux kernel AIO, so clustering is a
// Linux-only feature; the rest of Notary still builds and runs everywhere.
var ErrUnsupportedPlatform = errors.New("clustering is only supported on linux")

// ErrNotInitialized is returned by Start when a node that was not asked to
// bootstrap or join has no usable dqlite metadata. Starting such a node would
// otherwise bootstrap a fresh cluster and silently disjoin it from its own.
var ErrNotInitialized = errors.New("this node has no cluster state to resume: run `notary cluster bootstrap` or `notary cluster join` first")

// ErrAlreadyInitialized is returned by Start when a node asked to bootstrap or
// join already holds cluster data. Both form a new membership from scratch, so
// running either over existing state would strand whatever was there.
var ErrAlreadyInitialized = errors.New("this node already holds cluster state: move its state directory aside before bootstrapping or joining")

// Options configures a Notary cluster node.
type Options struct {
	// StateDir holds the node's dqlite data and its cluster-internal PKI. It is
	// created if it does not exist.
	StateDir string

	// Address is the address this node advertises to other cluster members for
	// dqlite and Raft traffic. It must be reachable by every other member.
	Address string

	// Bootstrap forms a brand new cluster with this node as its only voter.
	// Only `notary cluster bootstrap` sets it: every other caller must find an
	// initialized state directory or fail. Cluster PKI must already be provisioned.
	Bootstrap bool

	// Join lists the addresses of existing cluster members, as handed back by
	// the member that admitted this node.
	Join []string
}

// Role is the Raft role a cluster member holds.
type Role string

const (
	// RoleVoter participates in Raft consensus.
	RoleVoter Role = "voter"
	// RoleStandBy replicates the log without voting, so a lost voter can be
	// healed by promotion rather than a fresh join.
	RoleStandBy Role = "standby"
	// RoleSpare neither votes nor replicates. dqlite parks members here when the
	// cluster already has as many voters and stand-bys as it was configured for.
	RoleSpare Role = "spare"
)

// MemberInfo describes one cluster member as dqlite knows it. dqlite has no
// notion of the operator-assigned name; that lives in the cluster_members table.
type MemberInfo struct {
	// ID is dqlite's node ID. It is a uint64, so it is rendered as a decimal
	// string anywhere it is stored or displayed.
	ID      uint64
	Address string
	Role    Role
}

// Node is a running Notary cluster member.
type Node interface {
	// Open returns a handle to the named database in the cluster. All
	// connections are routed to the current Raft leader.
	Open(ctx context.Context, name string) (*sql.DB, error)

	// Ready blocks until the node has finished the tasks it starts at startup:
	// bootstrapping a new cluster, or joining an existing one.
	Ready(ctx context.Context) error

	// ID returns this node's dqlite node ID.
	ID() uint64

	// Address returns the address this node advertises to other members.
	Address() string

	// Members returns every member of the cluster with its current Raft role.
	Members(ctx context.Context) ([]MemberInfo, error)

	// Leader returns the member currently leading the Raft cluster, or nil if
	// there is no leader right now.
	Leader(ctx context.Context) (*MemberInfo, error)

	// Close shuts the node down, first handing over any voting role it holds so
	// the remaining members keep quorum.
	Close(ctx context.Context) error
}

func validateOptions(opts Options) error {
	if opts.StateDir == "" {
		return errors.New("cluster state directory is required")
	}
	return ParseAdvertiseAddress(opts.Address)
}
