package cmd

import (
	"log"
	"net/http"
	"os"
	"os/signal"

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
		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath:    appConfig.DBPath,
			Logger:          zap.L(),
			ApplyMigrations: appConfig.ShouldApplyMigrations,
		})
		if err != nil {
			log.Fatalf("couldn't initialize database: %s", err)
		}
		appEnv, err := config.InitializeAppEnvironment(appConfig, database)
		if err != nil {
			log.Fatalf("couldn't initialize app environment: %s", err)
		}
		l := appEnv.SystemLogger
		srv, err := server.New(appConfig, appEnv)
		if err != nil {
			l.Fatal("couldn't initialize server", zap.Error(err))
		}
		l.Info("Starting server at", zap.String("url", srv.Addr))
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			l.Fatal("HTTP server ListenAndServe", zap.Error(err))
		}
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

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().StringVarP(&configFilePath, "config", "c", "", "path to the configuration file")
	startCmd.Flags().BoolP("migrate-database", "m", false, "automatically apply database migrations if needed (use with caution)")

	err := startCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}
}
