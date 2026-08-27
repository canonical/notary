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
// uninitialized state directory unless Bootstrap or Join is set, so a node that
// has lost its state cannot quietly form a cluster of its own.
func Start(opts Options) (Node, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	if err := checkState(opts); err != nil {
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

	dqliteApp, err := app.New(dataDir, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to start cluster node: %w", err)
	}

	return &dqliteNode{app: dqliteApp}, nil
}

// nodePKI loads operator-provisioned cluster credentials. Missing files are
// treated as an uninitialized node: Notary never mints a cluster CA.
func nodePKI(opts Options) (*PKI, error) {
	pki, err := LoadPKI(opts.StateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	if err := pki.MatchesIdentity(opts.Address); err != nil {
		return nil, err
	}
	return pki, nil
}

// checkState decides whether the state directory is in the shape this start
// calls for. Bootstrapping and joining both build a membership from nothing and
// so require an empty directory; resuming requires dqlite metadata complete
// enough to identify the cluster this node belongs to.
func checkState(opts Options) error {
	forming := opts.Bootstrap || len(opts.Join) > 0

	occupied, err := HasState(opts.StateDir)
	if err != nil {
		return err
	}

	switch {
	case forming && occupied:
		return ErrAlreadyInitialized
	case !forming && !hasNodeIdentity(opts.StateDir):
		return ErrNotInitialized
	}

	return nil
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

// withLeader runs fn against a client connected to the current Raft leader.
// app.Client talks to this node's own socket, which has no cluster configuration
// when the node is not a voter, so membership and role changes go through here.
func (n *dqliteNode) withLeader(ctx context.Context, fn func(*client.Client) error) error {
	cli, err := n.app.Leader(ctx)
	if err != nil {
		return fmt.Errorf("failed to reach the cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck
	return fn(cli)
}

func (n *dqliteNode) Members(ctx context.Context) ([]MemberInfo, error) {
	var members []MemberInfo
	err := n.withLeader(ctx, func(cli *client.Client) error {
		nodes, err := cli.Cluster(ctx)
		if err != nil {
			return fmt.Errorf("failed to list cluster members: %w", err)
		}
		members = make([]MemberInfo, 0, len(nodes))
		for _, node := range nodes {
			members = append(members, MemberInfo{
				ID:      node.ID,
				Address: node.Address,
				Role:    roleFromNodeRole(node.Role),
			})
		}
		return nil
	})
	return members, err
}

func (n *dqliteNode) Leader(ctx context.Context) (*MemberInfo, error) {
	var leader *MemberInfo
	err := n.withLeader(ctx, func(cli *client.Client) error {
		info, err := cli.Leader(ctx)
		if err != nil {
			return fmt.Errorf("failed to identify the cluster leader: %w", err)
		}
		if info == nil {
			return nil
		}
		leader = &MemberInfo{
			ID:      info.ID,
			Address: info.Address,
			Role:    roleFromNodeRole(info.Role),
		}
		return nil
	})
	return leader, err
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
