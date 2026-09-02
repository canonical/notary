// Package cluster owns the local dqlite node used as Notary's store.
package cluster

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
)

const (
	databaseName = "notary"
	infoFile     = "info.yaml"
)

// serializes SNAP_INSTANCE_NAME around app.New so concurrent tests do not
// clobber the env var go-dqlite uses to name its TLS abstract socket.
var dqliteStartMu sync.Mutex

// Options configure a dqlite node.
type Options struct {
	// Dir is the dqlite data directory (db_path in config).
	Dir string
	// Address is the dqlite bind address (host:port).
	Address string
	// Name is the LXD-style cluster member name (cluster.name).
	Name string
	// Join is existing node addresses, used only on first start of an empty dir.
	Join []string
	// JoinToken is a token from `notary cluster add`. Used only on first start.
	JoinToken string
	// TLSCert and TLSKey are the shared cluster certificate (PEM). Required
	// when joining. Same pair on every node; not the HTTPS API cert.
	TLSCert []byte
	TLSKey  []byte
}

// Node is a running dqlite application node.
type Node struct {
	app *app.App
}

// HasState reports whether dir already holds dqlite identity.
func HasState(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, infoFile))
	return err == nil
}

// Start opens or creates a dqlite node. An empty directory becomes a one-node
// cluster. A directory with info.yaml is resumed.
func Start(opts Options) (*Node, error) {
	if opts.Dir == "" {
		return nil, errors.New("database directory is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	join := append([]string(nil), opts.Join...)
	if opts.JoinToken != "" {
		if HasState(opts.Dir) {
			return nil, errors.New("join token is only used the first time this node starts")
		}
		token, err := DecodeJoinToken(opts.JoinToken)
		if err != nil {
			return nil, err
		}
		if opts.Name != "" && opts.Name != token.ServerName {
			return nil, fmt.Errorf("cluster.name %q does not match join token name %q", opts.Name, token.ServerName)
		}
		if len(join) > 0 {
			return nil, errors.New("set either a join token or cluster.join addresses, not both")
		}
		join = token.Addresses
	}
	if len(join) > 0 && (len(opts.TLSCert) == 0 || len(opts.TLSKey) == 0) {
		return nil, errors.New("joining a cluster requires cluster TLS (cluster.tls.cert_path and key_path)")
	}
	if (len(opts.TLSCert) == 0) != (len(opts.TLSKey) == 0) {
		return nil, errors.New("cluster TLS certificate and key must both be set")
	}

	var appOpts []app.Option
	if opts.Address != "" {
		appOpts = append(appOpts, app.WithAddress(opts.Address))
	}
	if len(join) > 0 && !HasState(opts.Dir) {
		appOpts = append(appOpts, app.WithCluster(join))
	}
	if len(opts.TLSCert) > 0 {
		tlsOpt, err := withClusterTLS(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return nil, wrapJoinError(join, err)
		}
		appOpts = append(appOpts, tlsOpt)
	}

	var dqliteApp *app.App
	err := withNamespacedDqliteSocket(opts.Dir, func() error {
		var startErr error
		dqliteApp, startErr = app.New(opts.Dir, appOpts...)
		return startErr
	})
	if err != nil {
		return nil, wrapJoinError(join, fmt.Errorf("start dqlite: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := dqliteApp.Ready(ctx); err != nil {
		_ = dqliteApp.Close()
		return nil, wrapJoinError(join, fmt.Errorf("dqlite not ready: %w", err))
	}

	return &Node{app: dqliteApp}, nil
}

// Open returns a *sql.DB for the Notary database.
func (n *Node) Open(ctx context.Context) (*sql.DB, error) {
	db, err := n.app.Open(ctx, databaseName)
	if err != nil {
		return nil, fmt.Errorf("open dqlite database: %w", err)
	}
	return db, nil
}

// Address returns this node's dqlite address.
func (n *Node) Address() string {
	return n.app.Address()
}

// Handover transfers leadership and voting rights to another node when possible.
func (n *Node) Handover(ctx context.Context) error {
	if n == nil || n.app == nil {
		return nil
	}
	return n.app.Handover(ctx)
}

// Close hands over cluster roles when possible, then shuts down the node.
func (n *Node) Close() error {
	if n == nil || n.app == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handoverErr := n.Handover(ctx)
	closeErr := n.app.Close()
	n.app = nil
	if closeErr != nil {
		return closeErr
	}
	return handoverErr
}

func wrapJoinError(join []string, err error) error {
	if len(join) == 0 {
		return err
	}
	return fmt.Errorf("join cluster at %s: %w", strings.Join(join, ", "), err)
}

// withNamespacedDqliteSocket sets SNAP_INSTANCE_NAME for go-dqlite TLS binds.
// go-dqlite otherwise uses @dqlite-<node-id>; the bootstrap id is constant, so
// two one-node clusters on one host (or leftover test processes) collide.
// A real snap already sets SNAP_INSTANCE_NAME; leave it alone.
func withNamespacedDqliteSocket(dir string, fn func() error) error {
	if os.Getenv("SNAP_INSTANCE_NAME") != "" {
		return fn()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(abs))
	name := fmt.Sprintf("notary-%x", sum[:8])

	dqliteStartMu.Lock()
	defer dqliteStartMu.Unlock()
	if err := os.Setenv("SNAP_INSTANCE_NAME", name); err != nil {
		return err
	}
	defer os.Unsetenv("SNAP_INSTANCE_NAME") //nolint:errcheck
	return fn()
}

// FreeAddress returns a 127.0.0.1:port suitable for tests.
func FreeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr, nil
}
