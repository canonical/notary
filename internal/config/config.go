package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	eb "github.com/canonical/notary/internal/encryption_backend"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

// CreateAppContext opens and processes the given configuration yaml file by
// initializing all of the necessary components for the Notary application.
func CreateAppContext(filePath string) (*NotaryAppContext, error) {
	appContext := NotaryAppContext{}
	configYaml, err := os.ReadFile(filePath) // #nosec: G304
	if err != nil {
		return nil, err
	}
	c := ConfigYAML{}
	if err := yaml.Unmarshal(configYaml, &c); err != nil {
		return nil, err
	}
	if c.CertPath == "" {
		return nil, errors.New("`cert_path` is empty")
	}
	cert, err := os.ReadFile(c.CertPath)
	if err != nil {
		return nil, err
	}
	if c.KeyPath == "" {
		return nil, errors.New("`key_path` is empty")
	}
	key, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return nil, err
	}
	if c.DBPath == "" {
		return nil, errors.New("`db_path` is empty")
	}
	if c.ExternalHostname == "" {
		c.ExternalHostname = "localhost"
	}
	if c.Port == 0 {
		return nil, errors.New("`port` is empty")
	}
	if c.PebbleNotifications {
		_, err := exec.LookPath("pebble")
		if err != nil {
			return nil, fmt.Errorf("pebble binary not found: %w", err)
		}
	}
	if c.Logging == (LoggingConfigYaml{}) {
		c.Logging = LoggingConfigYaml{
			System: SystemLoggingConfigYaml{
				Level:  "debug",
				Output: "stdout",
			},
		}
	}
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !slices.Contains(validLogLevels, c.Logging.System.Level) {
		return nil, fmt.Errorf("invalid log level: %s", c.Logging.System.Level)
	}
	if c.EncryptionBackend == nil {
		return nil, errors.New("`encryption_backend` config is missing, it must be a map with backends, empty map means no encryption")
	}

	// initialize logger
	logger, err := initializeLogger(&c.Logging)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize logger: %w", err)
	}

	// initialize encryption backend
	backendType, backend, err := initializeEncryptionBackend(&c.EncryptionBackend, appContext.Logger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize encryption backend: %w", err)
	}

	appContext.Config = &c
	appContext.TLSCertificate = cert
	appContext.TLSPrivateKey = key
	appContext.Port = c.Port
	appContext.ExternalHostname = c.ExternalHostname
	appContext.DBPath = c.DBPath
	appContext.PebbleNotificationsEnabled = c.PebbleNotifications
	appContext.Logger = logger
	appContext.EncryptionBackend = backend
	appContext.EncryptionBackendType = backendType
	appContext.PublicConfig = &PublicConfigData{
		Port:                  c.Port,
		PebbleNotifications:   c.PebbleNotifications,
		LoggingLevel:          string(c.Logging.System.Level),
		LoggingOutput:         c.Logging.System.Output,
		EncryptionBackendType: backendType,
	}
	return &appContext, nil
}

func initializeEncryptionBackend(cfg *EncryptionBackendConfigYaml, logger *zap.Logger) (EncryptionBackendType, eb.EncryptionBackend, error) {
	// Encryption Backend is nil if the map is empty
	if len(*cfg) == 0 {
		return EncryptionBackendTypeNone, eb.NoEncryptionBackend{}, nil
	}
	// For now we just take the first backend in the map.
	var firstBackend NamedBackendConfigYaml
	for _, v := range *cfg {
		firstBackend = v
		break
	}

	switch {
	case firstBackend.Vault != nil:
		if firstBackend.Vault.Endpoint == "" {
			return "", nil, errors.New("endpoint is missing")
		}
		if firstBackend.Vault.Mount == "" {
			return "", nil, errors.New("mount is missing")
		}
		if firstBackend.Vault.KeyName == "" {
			return "", nil, errors.New("key_name is missing")
		}
		if (firstBackend.Vault.AppRoleID != "" || firstBackend.Vault.AppRoleSecretID != "") && firstBackend.Vault.Token != "" {
			return "", nil, errors.New("provide either approle_role_id and approle_secret_id or token, not both")
		}
		if firstBackend.Vault.AppRoleID != "" && firstBackend.Vault.AppRoleSecretID != "" {
			backend, err := eb.NewVaultBackendWithAppRole(
				firstBackend.Vault.Endpoint,
				firstBackend.Vault.Mount,
				firstBackend.Vault.KeyName,
				firstBackend.Vault.AppRoleID,
				firstBackend.Vault.AppRoleSecretID,
				firstBackend.Vault.TlsCaCertificate,
				firstBackend.Vault.TlsSkipVerify,
				logger,
			)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			return EncryptionBackendTypeVault, backend, err
		} else if firstBackend.Vault.Token != "" {
			backend, err := eb.NewVaultBackendWithToken(
				firstBackend.Vault.Endpoint,
				firstBackend.Vault.Mount,
				firstBackend.Vault.KeyName,
				firstBackend.Vault.Token,
				firstBackend.Vault.TlsCaCertificate,
				firstBackend.Vault.TlsSkipVerify,
				logger,
			)
			if err != nil {
				return "", nil, fmt.Errorf("failed to create Vault encryption backend: %w", err)
			}
			return EncryptionBackendTypeVault, backend, err
		} else {
			return "", nil, errors.New("failed to create Vault encryption backend: either approle_role_id and approle_secret_id or token must be provided")
		}
	case firstBackend.PKCS11 != nil:
		if firstBackend.PKCS11.LibPath == "" {
			return "", nil, errors.New("lib_path is missing")
		}
		if firstBackend.PKCS11.Pin == "" {
			return "", nil, errors.New("pin is missing")
		}
		if firstBackend.PKCS11.KeyID == 0 {
			return "", nil, errors.New("aes_encryption_key_id is missing")
		}
		backend, err := eb.NewPKCS11Backend(firstBackend.PKCS11.LibPath, firstBackend.PKCS11.Pin, firstBackend.PKCS11.KeyID)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create PKCS11 backend: %w", err)
		}
		return EncryptionBackendTypePKCS11, backend, err
	default:
		return "", nil, errors.New("invalid encryption backend type; must be 'vault' or 'pkcs11'")
	}
}

func initializeLogger(opts *LoggingConfigYaml) (*zap.Logger, error) {
	zapConfig := zap.NewProductionConfig()

	logLevel, err := zapcore.ParseLevel(string(opts.System.Level))
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	zapConfig.OutputPaths = []string{opts.System.Output}
	zapConfig.Level.SetLevel(logLevel)
	zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}
