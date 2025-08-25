package cmd

import (
	"fmt"

	"github.com/canonical/notary/version"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Notary",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Notary v%s\n", version.GetVersion())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
