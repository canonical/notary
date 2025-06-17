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

// VaultBackendConfigYaml extends BackendConfig for Vault-specific fields.
type VaultBackendConfigYaml struct {
	Endpoint     string `yaml:"endpoint"`
	Mount        string `yaml:"mount"`
	KeyName      string `yaml:"key_name"`
	RoleID       string `yaml:"role_id"`
	RoleSecretID string `yaml:"role_secret_id"`
	Token        string `yaml:"token"`
}

// PKCS11BackendConfigYaml extends BackendConfig for PKCS11-specific fields.
type PKCS11BackendConfigYaml struct {
	LibPath string  `yaml:"lib_path"`
	KeyID   *uint16 `yaml:"key_id"`
	Pin     string  `yaml:"pin"`
}

type NoneBackendConfigYaml struct {
}

type SystemLoggingConfigYaml struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type LoggingConfigYaml struct {
	System SystemLoggingConfigYaml `yaml:"system"`
}

// EncryptionBackendConfig represents the configuration for an encryption backend
type EncryptionBackendConfig struct {
	Type   BackendType              `yaml:"type"`
	PKCS11 *PKCS11BackendConfigYaml `yaml:"pkcs11,omitempty"`
	Vault  *VaultBackendConfigYaml  `yaml:"vault,omitempty"`
	None   *NoneBackendConfigYaml   `yaml:"none,omitempty"`
}

type ConfigYAML struct {
	KeyPath             string                  `yaml:"key_path"`
	CertPath            string                  `yaml:"cert_path"`
	ExternalHostname    string                  `yaml:"external_hostname"`
	DBPath              string                  `yaml:"db_path"`
	Port                int                     `yaml:"port"`
	PebbleNotifications bool                    `yaml:"pebble_notifications"`
	Logging             LoggingConfigYaml       `yaml:"logging"`
	EncryptionBackend   EncryptionBackendConfig `yaml:"encryption_backend"`
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
	None   *NoneBackendConfigYaml
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
		return Config{}, fmt.Errorf("`logging` is empty")
	}

	if c.Logging.System == (SystemLoggingConfigYaml{}) {
		return Config{}, fmt.Errorf("`system` is empty in logging config")
	}

	if c.Logging.System.Level == "" {
		return Config{}, fmt.Errorf("`level` is empty in logging config")
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
		return Config{}, fmt.Errorf("`output` is empty in logging config")
	}

	// Validate encryption backend config
	if c.EncryptionBackend.Type == "" {
		return Config{}, fmt.Errorf("encryption backend type is missing")
	}

	switch c.EncryptionBackend.Type {
	case Vault:
		if c.EncryptionBackend.Vault == nil {
			return Config{}, fmt.Errorf("vault configuration is missing")
		}
	case PKCS11:
		if c.EncryptionBackend.PKCS11 == nil {
			return Config{}, fmt.Errorf("pkcs11 configuration is missing")
		}
		if c.EncryptionBackend.PKCS11.LibPath == "" {
			return Config{}, fmt.Errorf("PKCS11 library is missing")
		}
		if c.EncryptionBackend.PKCS11.Pin == "" {
			return Config{}, fmt.Errorf("Pin is missing")
		}
		if c.EncryptionBackend.PKCS11.KeyID == nil {
			return Config{}, fmt.Errorf("key ID is missing")
		}
	case None:
		if c.EncryptionBackend.None != nil {
			return Config{}, fmt.Errorf("none backend does not accept configuration")
		}
	default:
		return Config{}, fmt.Errorf("unknown backend type: %s", c.EncryptionBackend.Type)
	}

	config.Cert = cert
	config.Key = key
	config.ExternalHostname = c.ExternalHostname
	config.DBPath = c.DBPath
	config.Port = c.Port
	config.PebbleNotificationsEnabled = c.PebbleNotifications
	config.Logging.System.Level = LoggingLevel(c.Logging.System.Level)
	config.Logging.System.Output = c.Logging.System.Output
	config.EncryptionBackend = BackendConfig{
		Type:   c.EncryptionBackend.Type,
		PKCS11: c.EncryptionBackend.PKCS11,
		Vault:  c.EncryptionBackend.Vault,
		None:   c.EncryptionBackend.None,
	}
	return config, nil
}
