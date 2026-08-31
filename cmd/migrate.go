package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database schema updates (applied automatically)",
	Long: `Schema updates now run automatically when Notary starts and opens dqlite.

The old goose-based migrate up/down/status commands are no longer used.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("schema updates are applied automatically on `notary start`; the migrate command is no longer used")
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
