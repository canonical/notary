package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	"github.com/canonical/notary/internal/db/migrations"
	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
)

var dsn string

// migrateCmd represents the migrate commands. Without a specific command, it will only display help.
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Manage database migrations",
	Long: `Manage the database migrations on the configured database.

Applying migrations and removing migrations modifies the given database to work with Notary.
Read the help messages of the subcommands for more information.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

// migrateUpCmd represents the migrate up command.
var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply database migrations",
	Long: `Apply database migrations in order.

Use with no argument to apply all migrations. Use with a version number to apply migrations up to that version.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		version, err := prepareGoose(args)
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			return err
		}
		if version == 0 {
			err = goose.UpContext(cmd.Context(), db, ".", goose.WithNoColor(true))
		} else {
			err = goose.UpToContext(cmd.Context(), db, ".", version, goose.WithNoColor(true))
		}
		if err != nil {
			return err
		}
		if err := db.Close(); err != nil {
			return err
		}
		return nil
	},
}

// migrateDownCmd represents the migrate down command.
var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Remove database migrations",
	Long: `Remove database migrations in order.


Use with no argument to apply all migrations.
Use with a version number to remove migrations up to that version.
0 will remove all migrations, which effectively drops all tables.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		version, err := prepareGoose(args)
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			return err
		}
		defer func() {
			if err := db.Close(); err != nil {
				panic(err)
			}
		}()
		if version == 0 {
			err = goose.DownContext(cmd.Context(), db, ".", goose.WithNoColor(true))
		} else {
			err = goose.DownToContext(cmd.Context(), db, ".", version, goose.WithNoColor(true))
		}
		if err != nil {
			return err
		}
		return nil
	},
}

// migrateStatusCmd represents the migrate status command.
var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show database migrations",
	Long: `Show the status of database migrations.

Will display the current migration version and the status of each migration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		goose.SetBaseFS(migrations.EmbedMigrations)
		err := goose.SetDialect("sqlite")
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			log.Fatal(err)
		}
		return goose.StatusContext(cmd.Context(), db, ".", goose.WithNoColor(true))
	},
}

func init() {
	migrateUpCmd.Flags().StringVarP(&dsn, "database-path", "d", "./notary.db", "A DSN for connecting to the database. Also accepts a path to a file, and will assume that the database is SQLite.")
	migrateDownCmd.Flags().StringVarP(&dsn, "database-path", "d", "./notary.db", "A DSN for connecting to the database. Also accepts a path to a file, and will assume that the database is SQLite.")
	migrateStatusCmd.Flags().StringVarP(&dsn, "database-path", "d", "./notary.db", "A DSN for connecting to the database. Also accepts a path to a file, and will assume that the database is SQLite.")
	
	if err := migrateUpCmd.MarkFlagRequired("database-path"); err != nil {
		log.Fatalf("Error marking database-path flag as required: %v", err)
	}
	if err := migrateDownCmd.MarkFlagRequired("database-path"); err != nil {
		log.Fatalf("Error marking database-path flag as required: %v", err)
	}
	if err := migrateStatusCmd.MarkFlagRequired("database-path"); err != nil {
		log.Fatalf("Error marking database-path flag as required: %v", err)
	}

	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateStatusCmd)

	rootCmd.AddCommand(migrateCmd)

}

func prepareGoose(args []string) (int64, error) {
	version := int64(0)
	if len(args) == 1 {
		versionArg, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("version must be a number")
		}
		version = versionArg
	}
	goose.SetBaseFS(migrations.EmbedMigrations)
	err := goose.SetDialect("sqlite")
	if err != nil {
		return 0, err
	}

	return version, nil
}
