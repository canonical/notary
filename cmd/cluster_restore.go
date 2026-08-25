package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	auditlog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var clusterRestoreFile string

// clusterRestoreCmd rebuilds a cluster from a backup archive.
var clusterRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Rebuild a cluster from a backup archive",
	Long: `Rebuilds a Notary cluster from an archive created by 'notary backup'.

This is a disaster-recovery procedure, not a live operation. Restoring bootstraps
a brand new single-node cluster on this node and loads the backup into it, so
this node must have no cluster state of its own: stop Notary everywhere and move
the state directory aside before running it.

The other nodes cannot be reattached to the cluster they used to be part of.
Once this command succeeds, wipe their state directories and run
'notary cluster join' against this node to bring them back.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := config.ParseConfig(cmd.Flags(), clusterConfigFilePath)
		if err != nil {
			return fmt.Errorf("couldn't parse and validate config: %w", err)
		}
		if !appConfig.ClusterConfig.Enabled {
			return errors.New("clustering is not enabled: use `notary restore` for a single-node deployment")
		}

		archivePath, err := filepath.Abs(clusterRestoreFile)
		if err != nil {
			return fmt.Errorf("invalid restore file path: %w", err)
		}

		logger, err := zap.NewProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		defer func() { _ = logger.Sync() }()
		auditLogger := auditlog.NewAuditLogger(logger)

		name, err := restoreCluster(cmd, appConfig.ClusterConfig, archivePath, logger)
		if err != nil {
			auditLogger.DatabaseRestoreFailed(archivePath, err.Error())
			return err
		}

		auditLogger.DatabaseRestored(archivePath)
		cmd.Printf("cluster restored from %s as a single node, %s\n", archivePath, name)
		cmd.Println("wipe the state directory of every other node and run `notary cluster join` on each to rebuild the cluster")

		return nil
	},
}

// restoreCluster bootstraps a fresh single-node cluster and loads a backup
// archive into it, returning the name recorded for the restored node.
func restoreCluster(cmd *cobra.Command, clusterConfig config.ClusterConfig, archivePath string, logger *zap.Logger) (string, error) {
	occupied, err := cluster.HasState(clusterConfig.StateDir)
	if err != nil {
		return "", err
	}
	if occupied {
		return "", fmt.Errorf("%q already holds cluster state: stop Notary on this node and move the directory aside before restoring", cluster.DataDir(clusterConfig.StateDir))
	}

	files, err := cluster.ExtractDump(archivePath)
	if err != nil {
		return "", err
	}

	// The dump is staged outside the state directory: dqlite owns its data
	// directory exclusively, and the backup is only ever read from here.
	stageDir, err := os.MkdirTemp("", "notary-restore-")
	if err != nil {
		return "", fmt.Errorf("failed to create a staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir) //nolint:errcheck

	sourcePath, err := cluster.StageDump(stageDir, files)
	if err != nil {
		return "", err
	}

	// Checked while the dump is still only staged. Committing a backup this
	// binary cannot serve would leave a bootstrapped cluster that `notary start`
	// then refuses to open, with the state directory occupied and the restore no
	// longer repeatable.
	embedded, err := db.EmbeddedSchemaVersion()
	if err != nil {
		return "", err
	}
	staged, err := db.DumpSchemaVersion(sourcePath)
	if err != nil {
		return "", err
	}
	if staged != embedded {
		return "", fmt.Errorf(
			"the backup is at migration %d but this binary is built for migration %d: restore it with a matching version of Notary",
			staged, embedded)
	}

	node, err := startClusterNode(clusterConfig, true, nil)
	if err != nil {
		return "", err
	}
	defer closeClusterNode(node, logger)

	ctx, cancel := context.WithTimeout(cmd.Context(), clusterReadyTimeout)
	defer cancel()

	if err := node.Ready(ctx); err != nil {
		return "", fmt.Errorf("couldn't reach cluster readiness: %w", err)
	}

	conn, err := node.Open(ctx, cluster.DatabaseName)
	if err != nil {
		return "", err
	}
	defer conn.Close() //nolint:errcheck

	// Migrations are not applied: the schema is part of the backup, and applying
	// them to an empty database first would leave nothing for the restore to
	// load into.
	if err := db.CopyDatabase(ctx, sourcePath, conn); err != nil {
		return "", err
	}

	database, err := db.NewDatabaseFromConn(conn, &db.DatabaseOpts{
		DatabasePath:    cluster.DatabaseName,
		Logger:          logger,
		ApplyMigrations: false,
	})
	if err != nil {
		return "", fmt.Errorf("couldn't open the restored database: %w", err)
	}

	return recordRestoredMember(database, node, clusterConfig.Address)
}

// recordRestoredMember replaces the restored membership records with the single
// node that now holds the cluster.
//
// The backup carries the membership of the cluster it was taken from, whose node
// IDs mean nothing here: this is a new cluster, and its only member is this
// node, under a new ID. Leaving the old rows in place would have the cluster API
// reporting members that no longer exist.
func recordRestoredMember(database *db.DatabaseRepository, node cluster.Node, address string) (string, error) {
	// The backup also carries the CA key of the cluster it came from, which does
	// not match the CA this node generated for itself while bootstrapping. Left
	// in place it would be used to sign joins against the wrong CA and every one
	// of them would be rejected; cleared, the node stores its own on first start.
	if err := database.DeleteClusterCAKey(); err != nil {
		return "", fmt.Errorf("couldn't clear the restored cluster CA key: %w", err)
	}

	members, err := database.ListClusterMembers()
	if err != nil {
		return "", fmt.Errorf("couldn't read the restored cluster members: %w", err)
	}

	name := address
	for _, member := range members {
		if member.Address == address {
			name = member.Name
		}
		if err := database.DeleteClusterMember(member.NodeID); err != nil {
			return "", fmt.Errorf("couldn't clear the restored cluster members: %w", err)
		}
	}

	nodeID := formatNodeID(node.ID())
	if _, err := database.CreateClusterMember(nodeID, name, address, time.Now().UTC()); err != nil {
		return "", fmt.Errorf("couldn't record the restored cluster member: %w", err)
	}

	return fmt.Sprintf("%s (node %s)", name, nodeID), nil
}
