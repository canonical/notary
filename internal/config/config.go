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

// EncryptionBackendConfigYaml can be either "none" or a map of named backends
type EncryptionBackendConfigYaml struct {
	IsNone   bool
	Backends map[string]NamedBackendConfigYaml
}

// UnmarshalYAML implements custom YAML unmarshaling to handle both string and map formats
// To handle the case of no encryption backend, we use a string value of "none"
func (e *EncryptionBackendConfigYaml) UnmarshalYAML(node *yaml.Node) error {
	var str string
	if err := node.Decode(&str); err == nil {
		if str == "none" {
			e.IsNone = true
			return nil
		}
		return fmt.Errorf("encryption_backend must be either 'none' or a map of named backend")
	}

	var backends map[string]NamedBackendConfigYaml
	if err := node.Decode(&backends); err != nil {
		return fmt.Errorf("encryption_backend must be either 'none' or a map of named backends")
	}

	if len(backends) == 0 {
		return fmt.Errorf("encryption backend configuration is missing")
	}

	e.IsNone = false
	e.Backends = backends
	return nil
}

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

	if c.EncryptionBackend.IsNone {
		backendConfig = BackendConfig{Type: None}
	} else if len(c.EncryptionBackend.Backends) > 0 {
		var selectedBackend NamedBackendConfigYaml
		// Until we support multiple backends, we only use the first one
		for _, selectedBackend = range c.EncryptionBackend.Backends {
			break
		}

		switch {
		case selectedBackend.Vault != nil:
			backendConfig = BackendConfig{
				Type:  Vault,
				Vault: selectedBackend.Vault,
			}
		case selectedBackend.PKCS11 != nil:
			if selectedBackend.PKCS11.LibPath == "" {
				return Config{}, errors.New("lib_path is missing")
			}
			if selectedBackend.PKCS11.Pin == "" {
				return Config{}, errors.New("pin is missing")
			}
			if selectedBackend.PKCS11.KeyID == nil {
				return Config{}, errors.New("aes_encryption_key_id is missing")
			}
			backendConfig = BackendConfig{
				Type:   PKCS11,
				PKCS11: selectedBackend.PKCS11,
			}
		default:
			return Config{}, errors.New("invalid backend type, should be either 'vault' or 'pkcs11'")
		}
	} else {
		return Config{}, errors.New("encryption_backend configuration is missing")
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
