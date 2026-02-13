package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	backupFile       string
	backupConfigPath string
)

// backupCmd represents the backup command
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a physical backup of the database",
	Long: `Create a physical backup of all the tables in the database.

The backup will be created as a tar.gz archive containing the database file.
The database configuration is read from the specified config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupFile == "" {
			return fmt.Errorf("backup file path is required")
		}

		backupDir := filepath.Dir(backupFile)
		if backupDir == "" || backupDir == "." {
			return fmt.Errorf("backup file must include a directory path")
		}

		absDir, err := filepath.Abs(backupDir)
		if err != nil {
			return fmt.Errorf("invalid backup directory path: %w", err)
		}

		info, err := os.Stat(absDir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("backup directory does not exist: %s", absDir)
			}
			return fmt.Errorf("cannot access backup directory: %w", err)
		}

		if !info.IsDir() {
			return fmt.Errorf("backup path is not a directory: %s", absDir)
		}

		logger, err := zap.NewProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		defer func() { _ = logger.Sync() }()

		database, err := db.NewDatabase(&db.DatabaseOpts{
			DatabasePath:    backupConfigPath,
			ApplyMigrations: false,
			Logger:          logger,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		archivePath, err := db.CreateBackup(database, backupDir)
		if err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}

		fmt.Printf("Backup created successfully: %s\n", archivePath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)

	backupCmd.Flags().StringVarP(&backupFile, "file", "f", "", "path where the backup archive will be created (directory path)")
	backupCmd.Flags().StringVarP(&backupConfigPath, "db-path", "d", "", "path to the database file")

	_ = backupCmd.MarkFlagRequired("file")
	_ = backupCmd.MarkFlagRequired("db-path")
}
