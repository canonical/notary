package cluster

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/canonical/go-dqlite/v3/client"
	"github.com/canonical/go-dqlite/v3/driver"
)

func clusterDial(certPEM, keyPEM []byte) (client.DialFunc, error) {
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return client.DefaultDialFunc, nil
	}
	_, dialTLS, err := clusterTLSConfigs(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return client.DialFuncWithTLS(client.DefaultDialFunc, dialTLS), nil
}

func connectLeader(ctx context.Context, dir string, certPEM, keyPEM []byte) (*client.Client, error) {
	store, err := client.NewYamlNodeStore(filepath.Join(dir, storeFile))
	if err != nil {
		return nil, fmt.Errorf("read cluster membership: %w", err)
	}
	dial, err := clusterDial(certPEM, keyPEM)
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
	store, err := client.NewYamlNodeStore(filepath.Join(dir, storeFile))
	if err != nil {
		return nil, fmt.Errorf("read cluster membership: %w", err)
	}
	dial, err := clusterDial(certPEM, keyPEM)
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
