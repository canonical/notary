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
	backupFile     string
	backupInsecure bool
	backupViper    = viper.New()
)

// backupCmd represents the backup command
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a physical backup of the database",
	Long: `Create a physical backup of all the tables in the database.

The backup will be created as a tar.gz archive containing the database file.
You must provide authentication credentials to access the Notary API.

Environment Variables:
  NOTARY_ADDR   Notary server address
  NOTARY_TOKEN  Authentication token for API access`,
	RunE: func(cmd *cobra.Command, args []string) error {
		endpoint := backupViper.GetString("addr")
		token := backupViper.GetString("token")
		
		if endpoint == "" {
			return fmt.Errorf("no server address provided. Set NOTARY_ADDR environment variable or use --addr flag")
		}
		if token == "" {
			return fmt.Errorf("no authentication token provided. Set NOTARY_TOKEN environment variable or use --token flag")
		}

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

		reqBody := map[string]string{
			"path": backupDir,
		}
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to prepare request: %w", err)
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: backupInsecure,
				},
			},
		}

		req, err := http.NewRequest("POST", endpoint+"/api/v1/backup", bytes.NewBuffer(jsonData))
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
			return fmt.Errorf("backup failed (status %d): %s", resp.StatusCode, string(body))
		}

        var parsed struct {
            Result string `json:"result"`
        }
        if err := json.Unmarshal(body, &parsed); err == nil && parsed.Result != "" {
            fmt.Printf("Backup created at: %s\n", parsed.Result)
        } else {
            fmt.Printf("Backup created\n")
        }
		return nil
	},
}

func init() {
	backupViper.SetEnvPrefix("NOTARY")
	backupViper.AutomaticEnv()
	
	backupCmd.Flags().StringVarP(&backupFile, "file", "f", "", "Path and file name for the physical backup archive")
	backupCmd.Flags().String("addr", "", "Notary server address")
	backupCmd.Flags().String("token", "", "Authentication token")
	backupCmd.Flags().BoolVarP(&backupInsecure, "insecure", "k", false, "Skip TLS certificate verification")

	if err := backupViper.BindPFlag("addr", backupCmd.Flags().Lookup("addr")); err != nil {
		log.Fatalf("Error binding addr flag: %v", err)
	}
	if err := backupViper.BindPFlag("token", backupCmd.Flags().Lookup("token")); err != nil {
		log.Fatalf("Error binding token flag: %v", err)
	}

	if err := backupCmd.MarkFlagRequired("file"); err != nil {
		log.Fatalf("Error marking file flag as required: %v", err)
	}

	rootCmd.AddCommand(backupCmd)
}
