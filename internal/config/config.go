package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/canonical/notary/internal/cluster"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ParseConfig reads, parses and validates the configuration file.
// It returns an AppConfig containing only configuration data without initializing subsystems.
func ParseConfig(cmdFlags *pflag.FlagSet, configFilePath string) (*AppConfig, error) {
	cfg, err := initializeServerConfig(cmdFlags, configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server config: %w", err)
	}
	if err := validateServerConfig(cfg); err != nil {
		return nil, fmt.Errorf("failed to validate server config: %w", err)
	}

	cert, err := os.ReadFile(cfg.GetString("cert_path"))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(cfg.GetString("key_path"))
	if err != nil {
		return nil, err
	}

	appConfig := &AppConfig{}
	appConfig.TLSCertificate = cert
	appConfig.TLSPrivateKey = key

	appConfig.Port = cfg.GetInt("port")
	appConfig.ExternalHostname = cfg.GetString("external_hostname")

	appConfig.DBPath = cfg.GetString("db_path")

	appConfig.ClusterConfig = ClusterConfig{
		Enabled:  cfg.GetBool("cluster.enabled"),
		StateDir: cfg.GetString("cluster.state_dir"),
		Address:  cfg.GetString("cluster.address"),
	}

	appConfig.ShouldEnablePebbleNotifications = cfg.GetBool("pebble_notifications")

	appConfig.LoggingConfig = cfg.Sub("logging")
	appConfig.TracingConfig = cfg.Sub("tracing")
	appConfig.OIDCConfig = parseOIDCConfigs(cfg)
	appConfig.EncryptionConfig = cfg.Sub("encryption_backend")

	return appConfig, nil
}

// parseOIDCConfigs reads `authentication.oidc`, accepting either a list of
// provider mappings or a single mapping. The single-mapping form is what
// existing single-provider config files use and keeps working unchanged.
func parseOIDCConfigs(cfg *viper.Viper) []*viper.Viper {
	raw := cfg.Get("authentication.oidc")
	entries, isList := raw.([]any)
	if !isList {
		if sub := cfg.Sub("authentication.oidc"); sub != nil {
			return []*viper.Viper{sub}
		}
		return nil
	}

	configs := make([]*viper.Viper, 0, len(entries))
	for _, entry := range entries {
		fields, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		sub := viper.New()
		for key, value := range fields {
			sub.Set(key, value)
		}
		configs = append(configs, sub)
	}
	return configs
}

// This function initializes the server config by merging the config file, command line options and environment variables.
// The precedence is as follows (from highest to lowest):
//  1. command line options
//  2. environment variables
//  3. config file
//  4. default values
//
// It then returns a viper instance containing the merged configuration.
func initializeServerConfig(cmdFlags *pflag.FlagSet, configFilePath string) (*viper.Viper, error) {
	v := viper.New()
	v.SetEnvPrefix("NOTARY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "*", "-", "*"))
	v.AutomaticEnv()

	v.SetDefault("external_hostname", "localhost")
	v.SetDefault("logging.system.level", "debug")
	v.SetDefault("logging.system.output", "stdout")
	v.SetDefault("logging.audit.output", "stdout")

	if configFilePath == "" {
		return nil, errors.New("config file path not provided")
	}
	v.SetConfigFile(configFilePath)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if err := v.BindPFlags(cmdFlags); err != nil {
		return nil, fmt.Errorf("failed to bind flags: %w", err)
	}

	return v, nil
}

// validateServerConfig makes sure that the expected configuration options are set.
func validateServerConfig(cfg *viper.Viper) error {
	if !cfg.IsSet("db_path") {
		return errors.New("`db_path` is empty")
	}
	if !cfg.IsSet("port") {
		return errors.New("`port` is empty")
	}
	if cfg.IsSet("pebble_notifications") && cfg.GetBool("pebble_notifications") {
		_, err := exec.LookPath("pebble")
		if err != nil {
			return fmt.Errorf("pebble binary not found: %w", err)
		}
	}
	if !cfg.IsSet("cert_path") {
		return errors.New("`cert_path` is empty")
	}
	if !cfg.IsSet("key_path") {
		return errors.New("`key_path` is empty")
	}
	if !cfg.IsSet("encryption_backend") {
		return errors.New("`encryption_backend` is empty")
	}
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if cfg.IsSet("logging.system.level") && !slices.Contains(validLogLevels, cfg.GetString("logging.system.level")) {
		return fmt.Errorf("invalid log level: %s", cfg.GetString("logging.system.level"))
	}
	if err := validateClusterConfig(cfg); err != nil {
		return err
	}
	if err := validateEncryptionBackendConfig(cfg.Sub("encryption_backend")); err != nil {
		return err
	}
	return nil
}

// validateClusterConfig validates the clustering configuration. Clustering is
// off unless `cluster.enabled` is explicitly true, so an existing config file
// keeps behaving exactly as it does today.
func validateClusterConfig(cfg *viper.Viper) error {
	if !cfg.GetBool("cluster.enabled") {
		return nil
	}
	if !cfg.IsSet("cluster.state_dir") {
		return errors.New("`cluster.state_dir` is empty")
	}
	if !cfg.IsSet("cluster.address") {
		return errors.New("`cluster.address` is empty")
	}
	if err := cluster.ParseAdvertiseAddress(cfg.GetString("cluster.address")); err != nil {
		return fmt.Errorf("`cluster.address`: %w", err)
	}
	return nil
}

// validateEncryptionBackendConfig validates the encryption backend configuration.
func validateEncryptionBackendConfig(encryptionCfg *viper.Viper) error {
	backendType := encryptionCfg.GetString("type")
	switch backendType {
	case "vault":
		if !encryptionCfg.IsSet("endpoint") {
			return errors.New("endpoint is missing")
		}
		if !encryptionCfg.IsSet("mount") {
			return errors.New("mount is missing")
		}
		if !encryptionCfg.IsSet("key_name") {
			return errors.New("key_name is missing")
		}
		if (!encryptionCfg.IsSet("approle_role_id") || !encryptionCfg.IsSet("secret_role_id")) && !encryptionCfg.IsSet("token") {
			return errors.New("provide either approle_role_id and approle_secret_id or token, not both")
		}
	case "pkcs11":
		if !encryptionCfg.IsSet("lib_path") {
			return errors.New("lib_path is missing")
		}
		if !encryptionCfg.IsSet("pin") {
			return errors.New("pin is missing")
		}
		if !encryptionCfg.IsSet("aes_encryption_key_id") {
			return errors.New("aes_encryption_key_id is missing")
		}
	case "none":
		// No validation needed for "none" backend
	default:
		return errors.New("invalid encryption backend type; must be 'none', 'vault' or 'pkcs11'")
	}
	return nil
}
