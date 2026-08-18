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

// Options configures a Notary cluster node.
type Options struct {
	// StateDir holds the node's dqlite data and its cluster-internal PKI. It is
	// created if it does not exist.
	StateDir string

	// Address is the address this node advertises to other cluster members for
	// dqlite and Raft traffic. It must be reachable by every other member.
	Address string

	// Join lists the addresses of existing cluster members. An empty Join
	// bootstraps a new cluster with this node as its only voter.
	Join []string

	// OnRolesAdjustment, if set, is called on this node each time dqlite
	// re-evaluates cluster roles, with the ID of the current leader. It is how
	// Notary learns that leadership has moved. It runs on dqlite's own loop, so
	// it must not block for long; an error is logged and otherwise ignored.
	OnRolesAdjustment func(leaderID uint64) error
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

	// Promote assigns the voter role to a member. Role convergence is otherwise
	// automatic; this exists so an operator can force it immediately.
	Promote(ctx context.Context, id uint64) error

	// Handover transfers a member's Raft responsibilities away, so that a member
	// being decommissioned can leave without forcing an election. It fails for a
	// member that is already unreachable, which is precisely when removal has to
	// go ahead without it.
	Handover(ctx context.Context, id uint64) error

	// Remove drops a member from the cluster.
	Remove(ctx context.Context, id uint64) error

	// Close shuts the node down, first handing over any voting role it holds so
	// the remaining members keep quorum.
	Close(ctx context.Context) error
}

func validateOptions(opts Options) error {
	if opts.StateDir == "" {
		return errors.New("cluster state directory is required")
	}
	if opts.Address == "" {
		return errors.New("cluster address is required")
	}
	return nil
}
