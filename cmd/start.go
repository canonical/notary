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
		appContext, err := config.CreateAppContext(cmd.Flags(), configFilePath)
		if err != nil {
			log.Fatalf("couldn't create app context: %s", err)
		}
		l := appContext.Logger

		// Initialize the database connection
		db, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath: appContext.DBPath,
			Backend:      appContext.EncryptionBackend,
			Logger:       appContext.Logger,
		})
		if err != nil {
			l.Fatal("couldn't initialize database", zap.Error(err))
		}

		// Initialize and run the API and webserver
		srv, err := server.New(&server.ServerOpts{
			TLSCertificate:            appContext.TLSCertificate,
			TLSPrivateKey:             appContext.TLSPrivateKey,
			Port:                      appContext.Port,
			Database:                  db,
			ExternalHostname:          appContext.ExternalHostname,
			EnablePebbleNotifications: appContext.PebbleNotificationsEnabled,
			Logger:                    appContext.Logger,
			PublicConfig:              appContext.PublicConfig,
		})
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
	err := startCmd.MarkFlagRequired("config")
	if err != nil {
		log.Fatalf("couldn't mark flag required: %s", err)
	}
}
