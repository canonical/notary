package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "notary",
	Short: "Notary is an x509 certificate management application",
	Long: `Notary is an open-source, enterprise TLS Certificate Management software that
provides a secure, reliable, and simple way to manage x.509 certificates for your
applications and services.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
