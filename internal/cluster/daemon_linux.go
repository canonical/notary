//go:build linux

package cluster

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/canonical/go-dqlite/v3/app"
	"github.com/canonical/go-dqlite/v3/client"
)

const (
	// defaultVoters and defaultStandBys are the Raft role targets go-dqlite
	// converges the cluster towards as members join and leave: three voters for
	// a quorum that tolerates one failure, plus two stand-bys ready to be
	// promoted.
	defaultVoters   = 3
	defaultStandBys = 2

	// maxOpenConns matches the connection limit the single-file SQLite path has
	// always used (internal/db/db_init.go), preserving the single-writer
	// assumption the query layer is built on.
	maxOpenConns = 2
)

// dqliteNode is the Linux implementation of Node, backed by go-dqlite's app
// package.
type dqliteNode struct {
	app *app.App
}

// Start brings up this node's dqlite instance. It refuses to run against an
// uninitialized state directory unless Bootstrap is set, so a node that has lost
// its state cannot quietly form a cluster of its own.
func Start(opts Options) (Node, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	dataDir := DataDir(opts.StateDir)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create cluster data directory: %w", err)
	}

	pki, err := nodePKI(opts)
	if err != nil {
		return nil, err
	}

	listen, dial := app.SimpleTLSConfig(pki.Certificate, pki.Pool)
	options := []app.Option{
		app.WithAddress(opts.Address),
		app.WithTLS(listen, dial),
		app.WithVoters(defaultVoters),
		app.WithStandBys(defaultStandBys),
	}
	if len(opts.Join) > 0 {
		options = append(options, app.WithCluster(opts.Join))
	}
	if opts.OnRolesAdjustment != nil {
		hook := opts.OnRolesAdjustment
		options = append(options, app.WithRolesAdjustmentHook(func(leader client.NodeInfo, _ []client.NodeInfo) error {
			return hook(leader.ID)
		}))
	}

	dqliteApp, err := app.New(dataDir, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to start cluster node: %w", err)
	}

	return &dqliteNode{app: dqliteApp}, nil
}

// nodePKI generates the cluster PKI when bootstrapping and otherwise insists it
// already exists. The distinction is what stops a node whose state directory was
// wiped from minting a new CA and bootstrapping a cluster of one.
func nodePKI(opts Options) (*PKI, error) {
	if opts.Bootstrap {
		return EnsurePKI(opts.StateDir, opts.Address)
	}

	pki, err := LoadPKI(opts.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}

	return pki, err
}

// Open returns a handle to the named database in the cluster.
func (n *dqliteNode) Open(ctx context.Context, name string) (*sql.DB, error) {
	conn, err := n.app.Open(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to open clustered database %q: %w", name, err)
	}
	conn.SetMaxIdleConns(maxOpenConns)
	conn.SetMaxOpenConns(maxOpenConns)

	return conn, nil
}

// Ready blocks until the node has finished bootstrapping or joining.
func (n *dqliteNode) Ready(ctx context.Context) error {
	if err := n.app.Ready(ctx); err != nil {
		return fmt.Errorf("cluster node did not become ready: %w", err)
	}
	return nil
}

// Address returns the address this node advertises to other members.
func (n *dqliteNode) Address() string {
	return n.app.Address()
}

// ID returns this node's dqlite node ID.
func (n *dqliteNode) ID() uint64 {
	return n.app.ID()
}

// Members returns every member of the cluster with its current Raft role.
//
// The client comes from app.Leader rather than app.Client: app.Client connects
// to this node's own dqlite socket, and a node that is not a voter has no Raft
// configuration to answer from, so it would report an empty cluster.
func (n *dqliteNode) Members(ctx context.Context) ([]MemberInfo, error) {
	cli, err := n.app.Leader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	nodes, err := cli.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster members: %w", err)
	}

	members := make([]MemberInfo, 0, len(nodes))
	for _, node := range nodes {
		members = append(members, MemberInfo{
			ID:      node.ID,
			Address: node.Address,
			Role:    roleFromNodeRole(node.Role),
		})
	}

	return members, nil
}

// Leader returns the member currently leading the cluster, or nil if there is
// no leader right now.
func (n *dqliteNode) Leader(ctx context.Context) (*MemberInfo, error) {
	cli, err := n.app.Leader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	leader, err := cli.Leader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to identify the cluster leader: %w", err)
	}
	if leader == nil {
		return nil, nil
	}

	return &MemberInfo{
		ID:      leader.ID,
		Address: leader.Address,
		Role:    roleFromNodeRole(leader.Role),
	}, nil
}

// Promote assigns the voter role to a member.
func (n *dqliteNode) Promote(ctx context.Context, id uint64) error {
	cli, err := n.app.Leader(ctx)
	if err != nil {
		return fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	if err := cli.Assign(ctx, id, client.Voter); err != nil {
		return fmt.Errorf("failed to promote cluster member %d: %w", id, err)
	}

	return nil
}

// Handover transfers a member's cluster responsibilities away so it can be
// removed without forcing an election or a quorum change on a live cluster
// (spec §1.5). It is the graceful half of a decommission; removing a member that
// is already gone must skip it, because it cannot succeed.
func (n *dqliteNode) Handover(ctx context.Context, id uint64) error {
	// go-dqlite's own primitive only works on the node it is called on.
	if id == n.app.ID() {
		if err := n.app.Handover(ctx); err != nil {
			return fmt.Errorf("failed to hand over cluster member %d: %w", id, err)
		}
		return nil
	}

	cli, err := n.app.Leader(ctx)
	if err != nil {
		return fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer func() { _ = cli.Close() }()

	leader, err := cli.Leader(ctx)
	if err != nil {
		return fmt.Errorf("failed to identify the cluster leader: %w", err)
	}
	if leader != nil && leader.ID == id {
		successor, err := otherVoter(ctx, cli, id)
		if err != nil {
			return err
		}
		if err := cli.Transfer(ctx, successor); err != nil {
			return fmt.Errorf("failed to transfer leadership away from cluster member %d: %w", id, err)
		}
		// The connection was to the old leader, so it is no longer the one that
		// can carry out the role change below.
		_ = cli.Close()
		if cli, err = n.app.Leader(ctx); err != nil {
			return fmt.Errorf("failed to reach the new cluster leader: %w", err)
		}
	}

	// Dropping to spare relinquishes the member's Raft responsibilities and lets
	// the remaining members converge before the membership itself changes.
	if err := cli.Assign(ctx, id, client.Spare); err != nil {
		return fmt.Errorf("failed to demote cluster member %d: %w", id, err)
	}

	return nil
}

// otherVoter picks a voter to hand leadership to, other than the one leaving.
func otherVoter(ctx context.Context, cli *client.Client, leaving uint64) (uint64, error) {
	nodes, err := cli.Cluster(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list cluster members: %w", err)
	}
	for _, node := range nodes {
		if node.ID != leaving && node.Role == client.Voter {
			return node.ID, nil
		}
	}

	return 0, fmt.Errorf("no other voter is available to take over from cluster member %d", leaving)
}

// Remove drops a member from the cluster. Handing over a leaving member's
// responsibilities is done separately (see Handover); a member removed from
// here may well be one that is already gone.
func (n *dqliteNode) Remove(ctx context.Context, id uint64) error {
	cli, err := n.app.Leader(ctx)
	if err != nil {
		return fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck

	if err := cli.Remove(ctx, id); err != nil {
		return fmt.Errorf("failed to remove cluster member %d: %w", id, err)
	}

	return nil
}

// roleFromNodeRole maps dqlite's role enum onto Notary's own, so nothing outside
// this file has to depend on go-dqlite's types.
func roleFromNodeRole(role client.NodeRole) Role {
	switch role {
	case client.Voter:
		return RoleVoter
	case client.StandBy:
		return RoleStandBy
	default:
		return RoleSpare
	}
}

// Close hands over this node's voting role, if it holds one, before shutting
// dqlite down. A failed handover is not fatal: the remaining members will
// re-converge their roles without this node, so shutdown continues either way.
func (n *dqliteNode) Close(ctx context.Context) error {
	handoverErr := n.app.Handover(ctx)
	if err := n.app.Close(); err != nil {
		return fmt.Errorf("failed to close cluster node: %w", err)
	}
	if handoverErr != nil {
		return fmt.Errorf("failed to hand over cluster node role: %w", handoverErr)
	}

	return nil
}
