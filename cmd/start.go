package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

// shutdownTimeout bounds how long in-flight requests have to finish once a
// shutdown signal arrives, before the cluster node is closed underneath them.
const shutdownTimeout = 30 * time.Second

// startCmd represents the start command which serves the Notary server
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the Notary server",
	Long: `Starts the Notary server daemon. Requires a valid configuration file.
Read more about what's required in the config file at
https://canonical-notary.readthedocs-hosted.com/en/latest/reference/config_file/`,

	// SilenceUsage because every failure below is a runtime one; printing the
	// flag list on top of it helps nobody.
	SilenceUsage: true,

	RunE: func(cmd *cobra.Command, args []string) error {
		appConfig, err := config.ParseConfig(cmd.Flags(), configFilePath)
		if err != nil {
			return fmt.Errorf("couldn't parse and validate config: %w", err)
		}
		// The reconciler is built before the database because a cluster node needs
		// its leadership hook at construction time, and the replicated database can
		// only be opened through that node. openDatabase arms it.
		acmeReconciler := acme.NewReconciler()
		database, clusterNode, closeCluster, err := openDatabase(cmd.Context(), appConfig, acmeReconciler)
		if err != nil {
			return fmt.Errorf("couldn't initialize database: %w", err)
		}
		// Everything past this point returns rather than calling Fatal: os.Exit
		// skips deferred functions, and this one hands the node's Raft
		// responsibilities over before it leaves.
		defer closeCluster()

		appEnv, err := config.InitializeAppEnvironment(cmd.Context(), appConfig, database, clusterNode, acmeReconciler)
		if err != nil {
			return fmt.Errorf("couldn't initialize app environment: %w", err)
		}
		l := appEnv.SystemLogger
		acmeReconciler.Attach(database, l, clusterNodeID(clusterNode))
		startHeartbeat(cmd.Context(), database, clusterNodeID(clusterNode), appConfig.ClusterConfig.Address, appEnv, l)
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
			return fmt.Errorf("couldn't initialize server: %w", err)
		}
		appEnv.AuditLogger.SystemStartup(srv.Addr)
		l.Info("Starting server at", zap.String("url", srv.Addr))

		// Installed before serving, not after: until this is armed the process
		// dies on the default disposition for these signals, so nothing deferred
		// runs and a cluster member leaves Raft abruptly instead of handing its
		// responsibilities over.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(signals)

		serverDone := make(chan struct{})
		shutdownComplete := make(chan struct{})
		go func() {
			defer close(shutdownComplete)

			select {
			case <-serverDone:
				// The server stopped on its own; there is nothing to shut down.
				return
			case received := <-signals:
				l.Info("shutdown signal received", zap.String("signal", received.String()))
			}

			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				l.Error("the server did not shut down cleanly", zap.Error(err))
			}
		}()

		serveErr := srv.ListenAndServeTLS("", "")
		close(serverDone)
		// Waited on so that closeCluster, deferred above, runs only once the
		// server has stopped accepting work.
		<-shutdownComplete

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("the HTTP server stopped unexpectedly: %w", serveErr)
		}

		appEnv.AuditLogger.SystemShutdown("server stopped")
		l.Info("server shutdown completed.")

		return nil
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
			DatabasePath: appConfig.DBPath,
			Logger:       zap.L(),
		})
		if err != nil {
			return nil, nil, nil, err
		}
		return database, nil, func() {}, nil
	}

	node, err := startClusterNode(appConfig.ClusterConfig, false, acmeReconciler.OnRolesAdjustment)
	if err != nil {
		return nil, nil, nil, err
	}

	readyCtx, cancel := context.WithTimeout(ctx, clusterReadyTimeout)
	defer cancel()

	database, err := openClusteredDatabase(readyCtx, node)
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
func startHeartbeat(ctx context.Context, database *db.DatabaseRepository, nodeID, address string, appEnv *config.AppEnvironment, logger *zap.Logger) {
	if nodeID == "" {
		return
	}

	beat := func() {
		sealed := appEnv.EncryptionRepository.SealState.Sealed()
		if err := database.RecordClusterMemberHeartbeat(nodeID, address, sealed, time.Now().UTC()); err != nil {
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
	err := startCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}
}
