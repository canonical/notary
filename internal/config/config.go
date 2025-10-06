package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	eb "github.com/canonical/notary/internal/encryption_backend"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// CreateAppContext opens and processes the given configuration yaml file by
// initializing all of the necessary components for the Notary application.
func CreateAppContext(cmdFlags *pflag.FlagSet, configFilePath string) (*NotaryAppContext, error) {
	cfg, err := initializeServerConfig(cmdFlags, configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server config: %w", err)
	}
	if err := validateServerConfig(cfg); err != nil {
		return nil, fmt.Errorf("failed to validate server config: %w", err)
	}
	appContext := NotaryAppContext{}

	cert, err := os.ReadFile(cfg.GetString("cert_path"))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(cfg.GetString("key_path"))
	if err != nil {
		return nil, err
	}

	// initialize system logger
	systemLogger, err := initializeLogger(
		cfg.GetString("logging.system.level"),
		cfg.GetString("logging.system.output"),
		cfg.GetString("logging.system.path"),
	)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize system logger: %w", err)
	}

	// initialize audit logger
	// Audit logs are always at INFO level
	auditLogger, err := initializeLogger(
		"info",
		cfg.GetString("logging.audit.output"),
		cfg.GetString("logging.audit.path"),
	)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize audit logger: %w", err)
	}
	// initialize encryption backend
	backendType, backend, err := initializeEncryptionBackend(cfg.Sub("encryption_backend"), systemLogger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize encryption backend: %w", err)
	}

	appContext.Port = cfg.GetInt("port")
	appContext.ExternalHostname = cfg.GetString("external_hostname")
	appContext.DBPath = cfg.GetString("db_path")
	appContext.ApplyMigrations = cfg.GetBool("migrate-database")
	appContext.PebbleNotificationsEnabled = cfg.GetBool("pebble_notifications")

	appContext.TLSCertificate = cert
	appContext.TLSPrivateKey = key
	appContext.SystemLogger = systemLogger
	appContext.AuditLogger = auditLogger
	appContext.EncryptionBackend = backend
	appContext.EncryptionBackendType = backendType
	appContext.PublicConfig = &PublicConfigData{
		Port:                  cfg.GetInt("port"),
		PebbleNotifications:   cfg.GetBool("pebble_notifications"),
		LoggingLevel:          cfg.GetString("logging.system.level"),
		LoggingOutput:         cfg.GetString("logging.system.output"),
		EncryptionBackendType: backendType,
	}
	return &appContext, nil
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

// ValidateServerConfig makes sure that the expected configuration options are set.
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
	if !cfg.IsSet("encryption_backend") {
		return errors.New("`encryption_backend` is empty")
	}
	return nil
}

// initializeEncryptionBackend creates and connects to an encryption backend based on the configuration.
func initializeEncryptionBackend(encryptionCfg *viper.Viper, logger *zap.Logger) (EncryptionBackendType, eb.EncryptionBackend, error) {
	backendType := encryptionCfg.GetString("type")
	switch backendType {
	case "vault":
		if !encryptionCfg.IsSet("endpoint") {
			return "", nil, errors.New("endpoint is missing")
		}
		if !encryptionCfg.IsSet("mount") {
			return "", nil, errors.New("mount is missing")
		}
		if !encryptionCfg.IsSet("key_name") {
			return "", nil, errors.New("key_name is missing")
		}
		if (!encryptionCfg.IsSet("approle_role_id") || !encryptionCfg.IsSet("secret_role_id")) && !encryptionCfg.IsSet("token") {
			return "", nil, errors.New("provide either approle_role_id and approle_secret_id or token, not both")
		}
		if encryptionCfg.IsSet("approle_role_id") && encryptionCfg.IsSet("secret_role_id") {
			backend, err := eb.NewVaultBackendWithAppRole(
				encryptionCfg.GetString("endpoint"),
				encryptionCfg.GetString("mount"),
				encryptionCfg.GetString("key_name"),
				encryptionCfg.GetString("approle_role_id"),
				encryptionCfg.GetString("secret_role_id"),
				encryptionCfg.GetString("tls_ca_certificate"),
				encryptionCfg.GetBool("tls_skip_verify"),
				logger,
			)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			return EncryptionBackendTypeVault, backend, err
		} else if encryptionCfg.IsSet("token") {
			backend, err := eb.NewVaultBackendWithToken(
				encryptionCfg.GetString("endpoint"),
				encryptionCfg.GetString("mount"),
				encryptionCfg.GetString("key_name"),
				encryptionCfg.GetString("token"),
				encryptionCfg.GetString("tls_ca_certificate"),
				encryptionCfg.GetBool("tls_skip_verify"),
				logger,
			)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			return EncryptionBackendTypeVault, backend, err
		} else {
			return "", nil, errors.New("failed to create Vault encryption backend: either approle_role_id and approle_secret_id or token must be provided")
		}
	case "pkcs11":
		if !encryptionCfg.IsSet("lib_path") {
			return "", nil, errors.New("lib_path is missing")
		}
		if !encryptionCfg.IsSet("pin") {
			return "", nil, errors.New("pin is missing")
		}
		if !encryptionCfg.IsSet("aes_encryption_key_id") {
			return "", nil, errors.New("aes_encryption_key_id is missing")
		}
		backend, err := eb.NewPKCS11Backend(
			encryptionCfg.GetString("lib_path"),
			encryptionCfg.GetString("pin"),
			encryptionCfg.GetUint16("aes_encryption_key_id"),
			logger,
		)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create PKCS11 backend: %w", err)
		}
		return EncryptionBackendTypePKCS11, backend, err
	case "none":
		return EncryptionBackendTypeNone, eb.NoEncryptionBackend{}, nil
	default:
		return "", nil, errors.New("invalid encryption backend type; must be 'none', 'vault' or 'pkcs11'")
	}
}

// initializeLogger creates and configures a logger based on the provided parameters.
// output can be "stdout", "stderr", or "file"
// path is required when output is "file"
func initializeLogger(level, output, path string) (*zap.Logger, error) {
	zapConfig := zap.NewProductionConfig()

	logLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	zapConfig.Level.SetLevel(logLevel)

	if output == "file" {
		if path == "" {
			return nil, fmt.Errorf("path is required when output is 'file'")
		}
		zapConfig.OutputPaths = []string{path}
	} else {
		zapConfig.OutputPaths = []string{output}
	}

	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}
