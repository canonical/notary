package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/canonical/go-dqlite/v3/client"
	"github.com/canonical/go-dqlite/v3/driver"
)

func connectLeader(ctx context.Context, dir string, t TransportTLS) (*client.Client, error) {
	store, err := client.NewYamlNodeStore(filepath.Join(dir, storeFile))
	if err != nil {
		return nil, fmt.Errorf("read cluster membership: %w", err)
	}
	dial, err := dialFunc(t)
	if err != nil {
		return nil, err
	}
	cli, err := client.FindLeader(ctx, store, client.WithDialFunc(dial))
	if err != nil {
		return nil, fmt.Errorf("could not reach cluster leader (is notary start running?): %w", err)
	}
	return cli, nil
}

// OpenClientDB opens the Notary SQL database as a client. The daemon must be running.
func OpenClientDB(ctx context.Context, dir string, certPEM, keyPEM []byte) (*sql.DB, error) {
	return OpenClientDBTLS(ctx, dir, tlsFromCertKey(certPEM, keyPEM))
}

// OpenClientDBTLS is OpenClientDB with shared or CA cluster TLS.
func OpenClientDBTLS(ctx context.Context, dir string, t TransportTLS) (*sql.DB, error) {
	store, err := client.NewYamlNodeStore(filepath.Join(dir, storeFile))
	if err != nil {
		return nil, fmt.Errorf("read cluster membership: %w", err)
	}
	dial, err := dialFunc(t)
	if err != nil {
		return nil, err
	}
	drv, err := driver.New(store, driver.WithDialFunc(dial))
	if err != nil {
		return nil, fmt.Errorf("dqlite driver: %w", err)
	}
	connector, err := drv.OpenConnector(databaseName)
	if err != nil {
		return nil, err
	}
	sqldb := sql.OpenDB(connector)
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("could not reach cluster database (is notary start running?): %w", err)
	}
	return sqldb, nil
}
