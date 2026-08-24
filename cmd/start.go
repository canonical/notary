package cmd

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/canonical/notary/internal/acme"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var configFilePath string

// startCmd represents the start command which serves the Notary server
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the Notary server",
	Long: `Starts the Notary server daemon. Requires a valid configuration file.
Read more about what's required in the config file at
https://canonical-notary.readthedocs-hosted.com/en/latest/reference/config_file/`,

	Run: func(cmd *cobra.Command, args []string) {
		appConfig, err := config.ParseConfig(cmd.Flags(), configFilePath)
		if err != nil {
			log.Fatalf("couldn't parse and validate config: %s", err)
		}
		// The reconciler is built before the database because a cluster node needs
		// its leadership hook at construction time, and the replicated database can
		// only be opened through that node. openDatabase arms it.
		acmeReconciler := acme.NewReconciler()
		database, clusterNode, closeCluster, err := openDatabase(cmd.Context(), appConfig, acmeReconciler)
		if err != nil {
			log.Fatalf("couldn't initialize database: %s", err)
		}
		defer closeCluster()
		appEnv, err := config.InitializeAppEnvironment(cmd.Context(), appConfig, database, clusterNode, acmeReconciler)
		if err != nil {
			log.Fatalf("couldn't initialize app environment: %s", err)
		}
		l := appEnv.SystemLogger
		acmeReconciler.Attach(database, l, clusterNodeID(clusterNode))
		startHeartbeat(cmd.Context(), database, clusterNodeID(clusterNode), appEnv, l)
		if clusterNode == nil {
			// Unclustered, so this process is the only one that has ever run an
			// attempt. Anything still recorded was interrupted by a previous crash.
			// Clustered deployments reconcile on leadership change instead, because
			// a live peer may legitimately own an attempt.
			if err := acmeReconciler.Reconcile(); err != nil {
				l.Error("couldn't reconcile interrupted ACME issuance attempts", zap.Error(err))
			}
		}
		srv, err := server.New(appConfig, appEnv)
		if err != nil {
			l.Fatal("couldn't initialize server", zap.Error(err))
		}
		appEnv.AuditLogger.SystemStartup(srv.Addr)
		l.Info("Starting server at", zap.String("url", srv.Addr))
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			l.Fatal("HTTP server ListenAndServe", zap.Error(err))
		}
		appEnv.AuditLogger.SystemShutdown("server stopped")
		l.Info("Shutting down server")

		// Listen for SIGINT to begin graceful shutdown
		mainThread := make(chan struct{})
		go func() {
			sigint := make(chan os.Signal, 1)
			signal.Notify(sigint, os.Interrupt)
			<-sigint
			l.Info("interrupt signal received")
			close(mainThread)
		}()

		// Await sigint listener to release main thread
		<-mainThread
		l.Info("server shutdown completed.")
	},
}

// openDatabase opens the repository the server runs against: the replicated
// dqlite database when clustering is enabled, otherwise the single SQLite file
// Notary has always used. It also returns the cluster node backing that
// database, which is nil when clustering is disabled. The returned function
// releases the cluster node and is a no-op in the unclustered case.
func openDatabase(ctx context.Context, appConfig *config.AppConfig, acmeReconciler *acme.Reconciler) (*db.DatabaseRepository, cluster.Node, func(), error) {
	if !appConfig.ClusterConfig.Enabled {
		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath:    appConfig.DBPath,
			Logger:          zap.L(),
			ApplyMigrations: appConfig.ShouldApplyMigrations,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		return database, nil, func() {}, nil
	}

	node, err := startClusterNode(appConfig.ClusterConfig, acmeReconciler.OnRolesAdjustment)
	if err != nil {
		return nil, nil, nil, err
	}

	readyCtx, cancel := context.WithTimeout(ctx, clusterReadyTimeout)
	defer cancel()

	database, err := openClusteredDatabase(readyCtx, node, appConfig.ShouldApplyMigrations)
	if err != nil {
		closeClusterNode(node, zap.L())
		return nil, nil, nil, err
	}

	return database, node, func() { closeClusterNode(node, zap.L()) }, nil
}

// clusterNodeID returns a cluster node's dqlite ID in decimal, or empty when
// there is no node.
func clusterNodeID(node cluster.Node) string {
	if node == nil {
		return ""
	}
	return formatNodeID(node.ID())
}

// heartbeatInterval is how often a member reports itself alive. It is half of
// db.OfflineThreshold, so a member has to miss two beats before its peers call
// it offline.
const heartbeatInterval = 10 * time.Second

// startHeartbeat keeps this member's liveness and seal state current until ctx
// is done. It does nothing when clustering is disabled, where there are no
// peers to report to.
func startHeartbeat(ctx context.Context, database *db.DatabaseRepository, nodeID string, appEnv *config.AppEnvironment, logger *zap.Logger) {
	if nodeID == "" {
		return
	}

	beat := func() {
		sealed := appEnv.EncryptionRepository.SealState.Sealed()
		if err := database.RecordClusterMemberHeartbeat(nodeID, sealed, time.Now().UTC()); err != nil {
			// A member that cannot write cannot reach the leader, which is exactly
			// what its peers should see it as: this beat is simply missed.
			logger.Warn("couldn't record cluster heartbeat",
				zap.String("node_id", nodeID), zap.Error(err))
		}
	}

	beat()
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				beat()
			}
		}
	}()
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().StringVarP(&configFilePath, "config", "c", "", "path to the configuration file")
	startCmd.Flags().BoolP("migrate-database", "m", false, "automatically apply database migrations if needed (use with caution)")

	err := startCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}
}
