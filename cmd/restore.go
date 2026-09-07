package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	auditlog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	restoreFile       string
	restoreConfigPath string
)

// restoreCmd represents the restore command
var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a database backup",
	Long: `Restore a tar.gz archive created by the backup command, replacing the data directory.

Stop Notary before restoring. This deletes the current data directory. The command fails if the daemon is still running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if restoreFile == "" {
			return fmt.Errorf("restore file path is required")
		}

		absPath, err := filepath.Abs(restoreFile)
		if err != nil {
			return fmt.Errorf("invalid restore file path: %w", err)
		}

		info, err := os.Stat(absPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("restore file does not exist: %s", absPath)
			}
			return fmt.Errorf("cannot access restore file: %w", err)
		}

		if info.IsDir() {
			return fmt.Errorf("restore path is a directory, not a file: %s", absPath)
		}

		logger, err := zap.NewProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		defer func() { _ = logger.Sync() }()
		auditLogger := auditlog.NewAuditLogger(logger)

		if err := db.RestoreBackup(restoreConfigPath, absPath); err != nil {
			auditLogger.DatabaseRestoreFailed(absPath, err.Error())
			return fmt.Errorf("failed to restore backup: %w", err)
		}

		auditLogger.DatabaseRestored(absPath)
		fmt.Println("Backup restored successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().StringVarP(&restoreFile, "file", "f", "", "path to the backup archive file to restore")
	restoreCmd.Flags().StringVarP(&restoreConfigPath, "db-path", "d", "", "path to the data directory")

	if err := restoreCmd.MarkFlagRequired("file"); err != nil {
		log.Fatalf("Error marking file flag as required: %v", err)
	}
	if err := restoreCmd.MarkFlagRequired("db-path"); err != nil {
		log.Fatalf("Error marking db-path flag as required: %v", err)
	}
}
