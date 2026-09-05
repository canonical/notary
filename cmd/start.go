package cmd

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var configFilePath string
var startJoinToken string

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
		joinToken := appConfig.ClusterJoinToken
		if startJoinToken != "" {
			joinToken = startJoinToken
		}
		apiAddr, err := cluster.JoinAPIAddress(appConfig.ClusterAddress, appConfig.Port, appConfig.ExternalHostname)
		if err != nil {
			log.Printf("cluster join tokens are unavailable until this is fixed: %s", err)
		}
		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath: appConfig.DBPath,
			Address:      appConfig.ClusterAddress,
			Name:         appConfig.ClusterName,
			Join:         appConfig.ClusterJoin,
			JoinToken:    joinToken,
			TLSCert:      appConfig.ClusterTLSCertificate,
			TLSKey:       appConfig.ClusterTLSPrivateKey,
			HTTPSCert:    appConfig.TLSCertificate,
			APIAddress:   apiAddr,
			Logger:       zap.L(),
		})
		if err != nil {
			log.Fatalf("couldn't initialize database: %s", err)
		}
		defer database.Close() //nolint:errcheck

		appEnv, err := config.InitializeAppEnvironment(appConfig, database)
		if err != nil {
			log.Fatalf("couldn't initialize app environment: %s", err)
		}
		l := appEnv.SystemLogger
		srv, err := server.New(appConfig, appEnv)
		if err != nil {
			l.Fatal("couldn't initialize server", zap.Error(err))
		}
		appEnv.AuditLogger.SystemStartup(srv.Addr)
		l.Info("Starting server at", zap.String("url", srv.Addr))

		go func() {
			sigint := make(chan os.Signal, 1)
			signal.Notify(sigint, os.Interrupt)
			<-sigint
			l.Info("interrupt signal received")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				l.Error("HTTP server shutdown", zap.Error(err))
			}
		}()

		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			l.Fatal("HTTP server ListenAndServe", zap.Error(err))
		}
		appEnv.AuditLogger.SystemShutdown("server stopped")
		l.Info("Shutting down server")
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().StringVarP(&configFilePath, "config", "c", "", "path to the configuration file")
	startCmd.Flags().StringVar(&startJoinToken, "join", "", "join token from 'notary cluster add <name>'")

	err := startCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}
}
