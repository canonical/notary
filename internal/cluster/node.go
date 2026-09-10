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
	// TLS is dqlite mTLS. SharedPair is the default (one cert for the cluster).
	// CAPeer is per-unit leaves under a dedicated CA. Nil means generate or
	// load the shared pair — never in CA mode.
	TLS TransportTLS
	// TLSCert and TLSKey are the shared cluster certificate (PEM). Required
	// when joining with cluster.join addresses. Same pair on every node; not
	// the HTTPS API cert. On first start of a new cluster they are generated
	// if empty. A join token fetches them over pinned HTTPS.
	// Deprecated: prefer TLS; still accepted and mapped to SharedPair.
	TLSCert []byte
	TLSKey  []byte
}

// Node is a running dqlite application node.
type Node struct {
	app *app.App
	TLS TransportTLS
}

// HasState reports whether dir already holds dqlite identity.
func HasState(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, infoFile))
	return err == nil
}

// discardFreshState removes the identity files app.New wrote in a directory
// that had no prior dqlite state, so a failed first start (for example a join
// whose addresses never became reachable) can be retried in the same
// directory instead of tripping "join token is only used the first time this
// node starts" on the next attempt.
func discardFreshState(dir string) error {
	var errs []error
	for _, f := range []string{infoFile, "cluster.yaml", "join"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", f, err))
		}
	}
	return errors.Join(errs...)
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
	// Snapshot before app.New can write info.yaml: whether this start resumes
	// an existing node decides if a failure may clean the directory.
	hadState := HasState(opts.Dir)
	join := append([]string(nil), opts.Join...)
	if opts.TLS == nil {
		opts.TLS = tlsFromCertKey(opts.TLSCert, opts.TLSKey)
	} else if len(opts.TLSCert) > 0 || len(opts.TLSKey) > 0 {
		if _, ok := opts.TLS.(CAPeer); ok {
			return nil, errors.New("cluster TLS cannot mix CA mode with a shared certificate")
		}
	}
	if _, isCA := opts.TLS.(CAPeer); isCA {
		if err := opts.TLS.(CAPeer).validate(); err != nil {
			return nil, err
		}
	} else {
		cert, key := presentCertKey(opts.TLS)
		if (len(cert) == 0) != (len(key) == 0) {
			return nil, errors.New("cluster TLS certificate and key must both be set")
		}
	}
	if opts.JoinToken != "" {
		if hadState {
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
		// Redeem consumes the one-time secret before app.New, so a rejected
		// token never reaches WithCluster.
		exchangeCtx, exchangeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		material, err := ExchangeJoinToken(exchangeCtx, opts.JoinToken)
		exchangeCancel()
		if err != nil {
			return nil, err
		}
		if material.ServerName != "" && material.ServerName != token.ServerName {
			return nil, fmt.Errorf("join credentials name %q does not match token name %q", material.ServerName, token.ServerName)
		}
		join = material.Join
		switch opts.TLS.(type) {
		case CAPeer:
			if len(material.TLSCert) != 0 || len(material.TLSKey) != 0 {
				return nil, errors.New("join token returned cluster key material; this node is configured for CA mode")
			}
		case SharedPair:
			if len(material.TLSCert) == 0 || len(material.TLSKey) == 0 {
				return nil, errors.New("join credentials are incomplete")
			}
			if cert, _, ok := opts.TLS.redeemPair(); ok && len(cert) > 0 {
				want, err := CertFingerprintPEM(material.TLSCert)
				if err != nil {
					return nil, err
				}
				got, err := CertFingerprintPEM(cert)
				if err != nil {
					return nil, err
				}
				if !strings.EqualFold(got, want) {
					return nil, fmt.Errorf("cluster TLS certificate does not match the certificate from the join server")
				}
			}
			opts.TLS = SharedPair{Cert: material.TLSCert, Key: material.TLSKey}
		default:
			if len(material.TLSKey) == 0 {
				return nil, errors.New("CA-mode join requires cluster.tls.ca_path, cert_path, key_path, and peer_san")
			}
			opts.TLS = SharedPair{Cert: material.TLSCert, Key: material.TLSKey}
		}
	} else if _, isCA := opts.TLS.(CAPeer); isCA {
		// CA mode never loads or generates a shared pair.
	} else if opts.TLS == nil {
		if hadState {
			if certPEM, keyPEM, err := LoadClusterTLS(opts.Dir); err == nil {
				opts.TLS = SharedPair{Cert: certPEM, Key: keyPEM}
			}
		} else if len(join) == 0 {
			certPEM, keyPEM, err := generateClusterTLS()
			if err != nil {
				return nil, err
			}
			opts.TLS = SharedPair{Cert: certPEM, Key: keyPEM}
		}
	}
	if len(join) > 0 && opts.TLS == nil {
		return nil, errors.New("joining a cluster requires cluster TLS (cluster.tls.cert_path and key_path)")
	}

	var appOpts []app.Option
	if opts.Address != "" {
		appOpts = append(appOpts, app.WithAddress(opts.Address))
	}
	if len(join) > 0 && !hadState {
		appOpts = append(appOpts, app.WithCluster(join))
	}
	if opts.TLS != nil {
		tlsOpt, err := withTransportTLS(opts.TLS)
		if err != nil {
			return nil, wrapJoinError(join, err)
		}
		appOpts = append(appOpts, tlsOpt)
	}

	var dqliteApp *app.App
	startErr := withNamespacedDqliteSocket(opts.Dir, func() error {
		var err error
		dqliteApp, err = app.New(opts.Dir, appOpts...)
		return err
	})
	if startErr != nil {
		startErr = wrapJoinError(join, fmt.Errorf("start dqlite: %w", startErr))
		if !hadState {
			if err := discardFreshState(opts.Dir); err != nil {
				startErr = fmt.Errorf("%w (also failed to clean up fresh state: %v)", startErr, err)
			}
		}
		if opts.JoinToken != "" {
			return nil, fmt.Errorf("%s: %w", JoinIncompleteMessage, startErr)
		}
		return nil, startErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := dqliteApp.Ready(ctx); err != nil {
		addr := dqliteApp.Address()
		_ = dqliteApp.Close()
		readyErr := err
		if !hadState {
			if cleanErr := discardFreshState(opts.Dir); cleanErr != nil {
				readyErr = fmt.Errorf("%w (also failed to clean up fresh state: %v)", readyErr, cleanErr)
			}
		}
		err = wrapJoinError(join, fmt.Errorf("dqlite not ready at %s: %w", addr, readyErr))
		if opts.JoinToken != "" {
			return nil, fmt.Errorf("%s: %w", JoinIncompleteMessage, err)
		}
		return nil, err
	}
	if opts.TLS != nil {
		if err := opts.TLS.persist(opts.Dir); err != nil {
			_ = dqliteApp.Close()
			return nil, err
		}
	}

	return &Node{app: dqliteApp, TLS: opts.TLS}, nil
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

// IsLeader reports whether this node currently holds the dqlite leadership.
// leaderAddr is the leader's dqlite address even when this node is not leader,
// so callers can tell an operator which member to retry on.
func (n *Node) IsLeader(ctx context.Context) (ok bool, leaderAddr string, err error) {
	if n == nil || n.app == nil {
		return false, "", fmt.Errorf("dqlite node is not running")
	}
	cli, err := n.app.FindLeader(ctx)
	if err != nil {
		return false, "", fmt.Errorf("find cluster leader: %w", err)
	}
	defer cli.Close() //nolint:errcheck
	info, err := cli.Leader(ctx)
	if err != nil {
		return false, "", fmt.Errorf("find cluster leader: %w", err)
	}
	if info == nil {
		return false, "", fmt.Errorf("cluster has no leader")
	}
	return info.ID == n.app.ID(), info.Address, nil
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
