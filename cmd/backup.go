package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	auditlog "github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/cluster"
	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/db"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	backupFile           string
	backupDBPath         string
	backupConfigFilePath string
)

// backupCmd represents the backup command
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a physical backup of the database",
	Long: `Create a physical backup of all the tables in the database.

The backup will be created as a tar.gz archive containing the database file.

Point the command at a database file with --db-path, or at a configuration file
with --config. For a clustered deployment --config is required: the backup is
taken from the current cluster leader over the network, so it can be run from
any member and needs no access to any node's database files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		backupDir, err := backupDirectory(backupFile)
		if err != nil {
			return err
		}

		logger, err := zap.NewProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}
		defer func() { _ = logger.Sync() }()
		auditLogger := auditlog.NewAuditLogger(logger)

		archivePath, err := createBackup(cmd, backupDir, logger)
		if err != nil {
			auditLogger.DatabaseBackupFailed(err.Error())
			return err
		}

		auditLogger.DatabaseBackupCreated(archivePath)
		cmd.Printf("Backup created successfully: %s\n", archivePath)
		return nil
	},
}

// createBackup writes a backup archive into backupDir, taking it from the
// cluster leader for a clustered deployment and from the local database file
// otherwise.
func createBackup(cmd *cobra.Command, backupDir string, logger *zap.Logger) (string, error) {
	databasePath := backupDBPath

	if backupConfigFilePath != "" {
		appConfig, err := config.ParseConfig(cmd.Flags(), backupConfigFilePath)
		if err != nil {
			return "", fmt.Errorf("couldn't parse and validate config: %w", err)
		}

		if appConfig.ClusterConfig.Enabled {
			ctx, cancel := context.WithTimeout(cmd.Context(), clusterTransferTimeout)
			defer cancel()

			files, err := cluster.DumpLeader(ctx, appConfig.ClusterConfig.StateDir)
			if err != nil {
				return "", err
			}

			return cluster.WriteDumpArchive(backupDir, files)
		}

		databasePath = appConfig.DBPath
	}

	database, err := db.NewDatabase(&db.DatabaseOpts{
		DatabasePath:    databasePath,
		ApplyMigrations: false,
		Logger:          logger,
	})
	if err != nil {
		return "", fmt.Errorf("failed to initialize database: %w", err)
	}
	defer database.Close() //nolint:errcheck

	archivePath, err := db.CreateBackup(database, backupDir)
	if err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	return archivePath, nil
}

// backupDirectory resolves the directory a backup archive should be written to.
func backupDirectory(file string) (string, error) {
	if file == "" {
		return "", errors.New("backup file path is required")
	}

	backupDir := filepath.Dir(file)
	if backupDir == "" || backupDir == "." {
		return "", errors.New("backup file must include a directory path")
	}

	absDir, err := filepath.Abs(backupDir)
	if err != nil {
		return "", fmt.Errorf("invalid backup directory path: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("backup directory does not exist: %s", absDir)
		}
		return "", fmt.Errorf("cannot access backup directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("backup path is not a directory: %s", absDir)
	}

	return backupDir, nil
}

func init() {
	rootCmd.AddCommand(backupCmd)

	backupCmd.Flags().StringVarP(&backupFile, "file", "f", "", "path where the backup archive will be created (directory path)")
	backupCmd.Flags().StringVarP(&backupDBPath, "db-path", "d", "", "path to the database file")
	backupCmd.Flags().StringVarP(&backupConfigFilePath, "config", "c", "", "path to the configuration file; required for a clustered deployment")

	backupCmd.MarkFlagsMutuallyExclusive("db-path", "config")
	backupCmd.MarkFlagsOneRequired("db-path", "config")

	if err := backupCmd.MarkFlagRequired("file"); err != nil {
		log.Fatalf("Error marking file flag as required: %v", err)
	}
}
