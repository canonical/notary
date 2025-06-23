package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

type BackendType string

const (
	Vault  BackendType = "vault"
	PKCS11 BackendType = "pkcs11"
	None   BackendType = "none"
)

// VaultBackendConfigYaml BackendConfig for Vault-specific fields.
type VaultBackendConfigYaml struct {
	Endpoint     string `yaml:"endpoint"`
	Mount        string `yaml:"mount"`
	KeyName      string `yaml:"key_name"`
	RoleID       string `yaml:"role_id"`
	RoleSecretID string `yaml:"role_secret_id"`
	Token        string `yaml:"token"`
}

// PKCS11BackendConfigYaml BackendConfig for PKCS11-specific fields.
type PKCS11BackendConfigYaml struct {
	LibPath string  `yaml:"lib_path"`
	KeyID   *uint16 `yaml:"aes_encryption_key_id"`
	Pin     string  `yaml:"pin"`
}

// NamedBackendConfigYaml represents a single named backend configuration
type NamedBackendConfigYaml struct {
	PKCS11 *PKCS11BackendConfigYaml `yaml:"pkcs11,omitempty"`
	Vault  *VaultBackendConfigYaml  `yaml:"vault,omitempty"`
}

type EncryptionBackendConfigYaml map[string]NamedBackendConfigYaml

type SystemLoggingConfigYaml struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type LoggingConfigYaml struct {
	System SystemLoggingConfigYaml `yaml:"system"`
}

type ConfigYAML struct {
	KeyPath             string                      `yaml:"key_path"`
	CertPath            string                      `yaml:"cert_path"`
	ExternalHostname    string                      `yaml:"external_hostname"`
	DBPath              string                      `yaml:"db_path"`
	Port                int                         `yaml:"port"`
	PebbleNotifications bool                        `yaml:"pebble_notifications"`
	Logging             LoggingConfigYaml           `yaml:"logging"`
	EncryptionBackend   EncryptionBackendConfigYaml `yaml:"encryption_backend"`
}

type LoggingLevel string

const (
	Debug LoggingLevel = "debug"
	Info  LoggingLevel = "info"
	Warn  LoggingLevel = "warn"
	Error LoggingLevel = "error"
	Fatal LoggingLevel = "fatal"
	Panic LoggingLevel = "panic"
)

type SystemLoggingConfig struct {
	Level  LoggingLevel
	Output string
}

type Logging struct {
	System SystemLoggingConfig
}

// BackendConfig holds the configuration for an encryption backend
type BackendConfig struct {
	Type   BackendType
	PKCS11 *PKCS11BackendConfigYaml
	Vault  *VaultBackendConfigYaml
}

type Config struct {
	Key                        []byte
	Cert                       []byte
	ExternalHostname           string
	DBPath                     string
	Port                       int
	PebbleNotificationsEnabled bool
	Logging                    Logging
	EncryptionBackend          BackendConfig
}

// Validate opens and processes the given yaml file, and catches errors in the process
func Validate(filePath string) (Config, error) {
	config := Config{}
	configYaml, err := os.ReadFile(filePath) // #nosec: G304
	if err != nil {
		return Config{}, err
	}
	c := ConfigYAML{}
	if err := yaml.Unmarshal(configYaml, &c); err != nil {
		return Config{}, err
	}
	if c.CertPath == "" {
		return Config{}, errors.New("`cert_path` is empty")
	}
	cert, err := os.ReadFile(c.CertPath)
	if err != nil {
		return Config{}, err
	}
	if c.KeyPath == "" {
		return Config{}, errors.New("`key_path` is empty")
	}
	key, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return Config{}, err
	}
	if c.ExternalHostname == "" {
		c.ExternalHostname = "localhost"
	}
	if c.DBPath == "" {
		return Config{}, errors.New("`db_path` is empty")
	}
	dbfile, err := os.OpenFile(c.DBPath, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return Config{}, err
	}
	err = dbfile.Close()
	if err != nil {
		return Config{}, err
	}
	if c.Port == 0 {
		return Config{}, errors.New("`port` is empty")
	}
	if c.PebbleNotifications {
		_, err := exec.LookPath("pebble")
		if err != nil {
			return Config{}, fmt.Errorf("pebble binary not found: %w", err)
		}
	}

	if c.Logging == (LoggingConfigYaml{}) {
		return Config{}, errors.New("`logging` is empty")
	}

	if c.Logging.System == (SystemLoggingConfigYaml{}) {
		return Config{}, errors.New("`system` is empty in logging config")
	}

	if c.Logging.System.Level == "" {
		return Config{}, errors.New("`level` is empty in logging config")
	}

	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	valid := false
	for _, level := range validLogLevels {
		if c.Logging.System.Level == level {
			valid = true
			break
		}
	}
	if !valid {
		return Config{}, fmt.Errorf("invalid log level: %s", c.Logging.System.Level)
	}

	if c.Logging.System.Output == "" {
		return Config{}, errors.New("`output` is empty in logging config")
	}

	var backendConfig BackendConfig

	if c.EncryptionBackend == nil {
		return Config{}, errors.New("`encryption_backend` config is missing, it must be a map with backends, empty map means no encryption")
	}

	if len(c.EncryptionBackend) == 0 {
		backendConfig = BackendConfig{Type: None}
	} else {
		var selected NamedBackendConfigYaml
		for _, v := range c.EncryptionBackend {
			selected = v
			break
		}

		switch {
		case selected.Vault != nil:
			backendConfig = BackendConfig{
				Type:  Vault,
				Vault: selected.Vault,
			}
		case selected.PKCS11 != nil:
			if selected.PKCS11.LibPath == "" {
				return Config{}, errors.New("lib_path is missing")
			}
			if selected.PKCS11.Pin == "" {
				return Config{}, errors.New("pin is missing")
			}
			if selected.PKCS11.KeyID == nil {
				return Config{}, errors.New("aes_encryption_key_id is missing")
			}
			backendConfig = BackendConfig{
				Type:   PKCS11,
				PKCS11: selected.PKCS11,
			}
		default:
			return Config{}, fmt.Errorf("invalid encryption backend type; must be 'vault' or 'pkcs11'")
		}
	}

	config.Cert = cert
	config.Key = key
	config.ExternalHostname = c.ExternalHostname
	config.DBPath = c.DBPath
	config.Port = c.Port
	config.PebbleNotificationsEnabled = c.PebbleNotifications
	config.Logging.System.Level = LoggingLevel(c.Logging.System.Level)
	config.Logging.System.Output = c.Logging.System.Output
	config.EncryptionBackend = backendConfig
	return config, nil
}
