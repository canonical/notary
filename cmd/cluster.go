package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// clusterReadyTimeout bounds how long a command waits for the local dqlite node
// to finish bootstrapping or joining before giving up.
const clusterReadyTimeout = 30 * time.Second

var clusterConfigFilePath string

var clusterBootstrapName string

// clusterCmd groups the commands that manage Notary's dqlite cluster.
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage the Notary cluster",
	Long:  `Manage the dqlite cluster backing a highly available Notary deployment.`,
}

// clusterBootstrapCmd initializes a new cluster with this node as its only member.
var clusterBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Initialize a new cluster with this node as its only member",
	Long: `Initializes a new Notary cluster: generates the cluster-internal PKI, starts
this node as the sole dqlite voter, and applies the database migrations.

Run this once, on the first node only. Every other node joins an existing
cluster instead. Requires a configuration file with clustering enabled.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := config.ParseConfig(cmd.Flags(), clusterConfigFilePath)
		if err != nil {
			return fmt.Errorf("couldn't parse and validate config: %w", err)
		}
		if !appConfig.ClusterConfig.Enabled {
			return errors.New("clustering is not enabled: set `cluster.enabled` to true in the config file")
		}

		node, err := startClusterNode(appConfig.ClusterConfig, nil)
		if err != nil {
			return err
		}
		defer closeClusterNode(node, zap.L())

		ctx, cancel := context.WithTimeout(cmd.Context(), clusterReadyTimeout)
		defer cancel()

		database, err := openClusteredDatabase(ctx, node, true)
		if err != nil {
			return err
		}
		defer database.Close() //nolint:errcheck

		name := clusterBootstrapName
		if name == "" {
			name = appConfig.ClusterConfig.Address
		}
		nodeID := formatNodeID(node.ID())
		if _, err := database.CreateClusterMember(nodeID, name, appConfig.ClusterConfig.Address, time.Now().UTC()); err != nil {
			return fmt.Errorf("bootstrapped the cluster but couldn't record the member name: %w", err)
		}

		cmd.Printf("cluster bootstrapped at %s as %s (node %s)\n", node.Address(), name, nodeID)

		return nil
	},
}

// startClusterNode brings up this node's dqlite instance from the cluster config.
//
// onRolesAdjustment, if non-nil, is called with the current leader's ID each
// time dqlite re-evaluates cluster roles. Only the server passes one; the
// short-lived CLI commands have no use for leadership notifications.
func startClusterNode(clusterConfig config.ClusterConfig, onRolesAdjustment func(leaderID uint64) error) (cluster.Node, error) {
	node, err := cluster.Start(cluster.Options{
		StateDir:          clusterConfig.StateDir,
		Address:           clusterConfig.Address,
		OnRolesAdjustment: onRolesAdjustment,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't start cluster node: %w", err)
	}

	return node, nil
}

// openClusteredDatabase waits for the node to be ready, then opens Notary's
// replicated database through it and initializes it exactly as the single-file
// path does.
func openClusteredDatabase(ctx context.Context, node cluster.Node, applyMigrations bool) (*db.DatabaseRepository, error) {
	if err := node.Ready(ctx); err != nil {
		return nil, fmt.Errorf("couldn't reach cluster readiness: %w", err)
	}

	conn, err := node.Open(ctx, cluster.DatabaseName)
	if err != nil {
		return nil, fmt.Errorf("couldn't open clustered database: %w", err)
	}

	database, err := db.NewDatabaseFromConn(conn, &db.DatabaseOpts{
		DatabasePath:    cluster.DatabaseName,
		Logger:          zap.L(),
		ApplyMigrations: applyMigrations,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize clustered database: %w", err)
	}

	return database, nil
}

// closeClusterNode shuts a node down, logging rather than returning any error so
// it can be deferred on shutdown paths.
func closeClusterNode(node cluster.Node, logger *zap.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), clusterReadyTimeout)
	defer cancel()

	if err := node.Close(ctx); err != nil {
		logger.Error("couldn't cleanly shut down cluster node", zap.Error(err))
	}
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(clusterBootstrapCmd)
	clusterCmd.AddCommand(clusterTokenCmd)
	clusterTokenCmd.AddCommand(clusterTokenCreateCmd)
	clusterCmd.AddCommand(clusterJoinCmd)
	clusterCmd.AddCommand(clusterPromoteCmd)
	clusterCmd.AddCommand(clusterRemoveCmd)
	clusterCmd.AddCommand(clusterStatusCmd)
	clusterCmd.AddCommand(clusterRestoreCmd)

	clusterBootstrapCmd.Flags().StringVarP(&clusterConfigFilePath, "config", "c", "", "path to the configuration file")
	clusterBootstrapCmd.Flags().StringVar(&clusterBootstrapName, "name", "", "name to record for this member (defaults to its cluster address)")

	if err := clusterBootstrapCmd.MarkFlagRequired("config"); err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}

	clusterRestoreCmd.Flags().StringVarP(&clusterConfigFilePath, "config", "c", "", "path to the configuration file")
	clusterRestoreCmd.Flags().StringVarP(&clusterRestoreFile, "file", "f", "", "path to the backup archive to restore")

	for _, flag := range []string{"config", "file"} {
		if err := clusterRestoreCmd.MarkFlagRequired(flag); err != nil {
			log.Fatalf("couldn't mark flag required: %s", err)
		}
	}

	// The commands below drive a node that is already running, so they go
	// through its admin API rather than opening dqlite themselves.
	for _, cmd := range []*cobra.Command{clusterTokenCreateCmd, clusterPromoteCmd, clusterRemoveCmd, clusterStatusCmd} {
		cmd.Flags().StringVarP(&clusterConfigFilePath, "config", "c", "", "path to the configuration file")
		cmd.Flags().StringVar(&clusterAPIToken, "token", "", "admin API token (defaults to the "+apiTokenEnvVar+" environment variable)")
		if err := cmd.MarkFlagRequired("config"); err != nil {
			log.Fatalf("couldn't mark flag required: %s", err)
		}
	}

	clusterTokenCreateCmd.Flags().StringVar(&clusterTokenRole, "role", "standby", `role the new member should hold: "voter" or "standby"`)
	clusterTokenCreateCmd.Flags().DurationVar(&clusterTokenTTL, "ttl", time.Hour, "how long the token stays valid")
	clusterTokenCreateCmd.Flags().BoolVarP(&clusterTokenQuiet, "quiet", "q", false, "print only the token, for scripting")

	clusterRemoveCmd.Flags().BoolVar(&clusterRemoveForce, "force", false, "skip the graceful handover; for a member that is already gone")

	clusterJoinCmd.Flags().StringVarP(&clusterConfigFilePath, "config", "c", "", "path to the configuration file")
	clusterJoinCmd.Flags().StringVar(&clusterJoinAddress, "address", "", "admin API address (host:port) of an existing cluster member")
	clusterJoinCmd.Flags().StringVar(&clusterJoinName, "name", "", "name to record for this member (defaults to its cluster address)")
	clusterJoinCmd.Flags().StringVar(&clusterJoinCACert, "ca-cert", "", "PEM certificate to verify the existing member's API against")

	for _, flag := range []string{"config", "address"} {
		if err := clusterJoinCmd.MarkFlagRequired(flag); err != nil {
			log.Fatalf("couldn't mark flag required: %s", err)
		}
	}
}
