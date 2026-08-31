// Package cluster owns the local dqlite node used as Notary's store.
//
// Stage 1 is a single node: an empty directory is bootstrapped, an existing
// directory is resumed. sqlair and OpenFGA use the *sql.DB from Open.
package cluster

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
)

const (
	databaseName = "notary"
	infoFile     = "info.yaml"
)

// Options configure a dqlite node.
type Options struct {
	// Dir is the dqlite data directory (db_path in config).
	Dir string
	// Address is the dqlite bind address (host:port).
	Address string
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

	var appOpts []app.Option
	if opts.Address != "" {
		appOpts = append(appOpts, app.WithAddress(opts.Address))
	}

	dqliteApp, err := app.New(opts.Dir, appOpts...)
	if err != nil {
		return nil, fmt.Errorf("start dqlite: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := dqliteApp.Ready(ctx); err != nil {
		_ = dqliteApp.Close()
		return nil, fmt.Errorf("dqlite not ready: %w", err)
	}

	return &Node{app: dqliteApp}, nil
}

// Open returns a *sql.DB for the Notary database (sqlair / OpenFGA).
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

// Close shuts down the dqlite node.
func (n *Node) Close() error {
	if n == nil || n.app == nil {
		return nil
	}
	return n.app.Close()
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
