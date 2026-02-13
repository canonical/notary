package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

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
	Long: `Restore the backup replacing the current database which will be deleted.

The backup archive must be a tar.gz file created by the backup command.

WARNING: This operation will replace the current database. Make sure to back up
your current database before restoring.`,
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

		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath:    restoreConfigPath,
			ApplyMigrations: false,
			Logger:          logger,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		if err := db.RestoreBackup(database, absPath); err != nil {
			return fmt.Errorf("failed to restore backup: %w", err)
		}

		fmt.Println("Backup restored successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().StringVarP(&restoreFile, "file", "f", "", "path to the backup archive file to restore")
	restoreCmd.Flags().StringVarP(&restoreConfigPath, "db-path", "d", "", "path to the database file")

	if err := restoreCmd.MarkFlagRequired("file"); err != nil {
		log.Fatalf("Error marking file flag as required: %v", err)
	}
	if err := restoreCmd.MarkFlagRequired("db-path"); err != nil {
		log.Fatalf("Error marking db-path flag as required: %v", err)
	}
}
