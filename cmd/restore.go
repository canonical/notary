package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	restoreFile     string
	restoreInsecure bool
	restoreViper    = viper.New()
)

// restoreCmd represents the restore command
var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a database backup",
	Long: `Restore the backup replacing the current database which will be deleted.

The backup archive must be a tar.gz file created by the backup command.
You must provide authentication credentials to access the Notary API.

WARNING: This operation will replace the current database. Make sure to back up
your current database before restoring.

Environment Variables:
  NOTARY_ADDR   Notary server address
  NOTARY_TOKEN  Authentication token for API access`,
	RunE: func(cmd *cobra.Command, args []string) error {
		endpoint := restoreViper.GetString("addr")
		token := restoreViper.GetString("token")
		
		if endpoint == "" {
			return fmt.Errorf("no server address provided. Set NOTARY_ADDR environment variable or use --addr flag")
		}
		if token == "" {
			return fmt.Errorf("no authentication token provided. Set NOTARY_TOKEN environment variable or use --token flag")
		}

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
		
		if ext := filepath.Ext(restoreFile); ext != ".gz" && ext != ".tar" {
			log.Printf("Warning: restore file does not have .tar.gz or .gz extension: %s", restoreFile)
		}

		reqBody := map[string]string{
			"file": absPath,
		}
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to prepare request: %w", err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: restoreInsecure,
				},
			},
		}

		req, err := http.NewRequest("POST", endpoint+"/api/v1/restore", bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("restore failed (status %d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("Backup %s restored\n", restoreFile)
		return nil
	},
}

func init() {
	restoreViper.SetEnvPrefix("NOTARY")
	restoreViper.AutomaticEnv()
	
	restoreCmd.Flags().StringVarP(&restoreFile, "file", "f", "", "Path to the backup archive file")
	restoreCmd.Flags().String("addr", "", "Notary server address")
	restoreCmd.Flags().String("token", "", "Authentication token")
	restoreCmd.Flags().BoolVarP(&restoreInsecure, "insecure", "k", false, "Skip TLS certificate verification")

	if err := restoreViper.BindPFlag("addr", restoreCmd.Flags().Lookup("addr")); err != nil {
		log.Fatalf("Error binding addr flag: %v", err)
	}
	if err := restoreViper.BindPFlag("token", restoreCmd.Flags().Lookup("token")); err != nil {
		log.Fatalf("Error binding token flag: %v", err)
	}

	if err := restoreCmd.MarkFlagRequired("file"); err != nil {
		log.Fatalf("Error marking file flag as required: %v", err)
	}

	rootCmd.AddCommand(restoreCmd)
}

