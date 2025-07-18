package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	"gopkg.in/yaml.v3"
)

type EncryptionBackendType string

const (
	Vault  EncryptionBackendType = "vault"
	PKCS11 EncryptionBackendType = "pkcs11"
	None   EncryptionBackendType = "none"
)

// VaultBackendConfigYaml BackendConfig for Vault-specific fields.
type VaultBackendConfigYaml struct {
	Endpoint         string `yaml:"endpoint"`
	Mount            string `yaml:"mount"`
	KeyName          string `yaml:"key_name"`
	Token            string `yaml:"token"`
	AppRoleID        string `yaml:"approle_role_id"`
	AppRoleSecretID  string `yaml:"approle_secret_id"`
	TlsCaCertificate string `yaml:"tls_ca_cert,omitempty"`     // Optional path to a CA file for Vault TLS verification
	TlsSkipVerify    bool   `yaml:"tls_skip_verify,omitempty"` // Optional flag to skip TLS verification
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

// EncryptionBackend holds the configuration for an encryption backend
type EncryptionBackend struct {
	Type   EncryptionBackendType
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
	EncryptionBackend          EncryptionBackend
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
		c.Logging = LoggingConfigYaml{
			System: SystemLoggingConfigYaml{
				Level:  "debug",
				Output: "stdout",
			},
		}
	}

	if c.Logging.System == (SystemLoggingConfigYaml{}) {
		return Config{}, errors.New("`system` is empty in logging config")
	}

	if c.Logging.System.Level == "" {
		return Config{}, errors.New("`level` is empty in logging config")
	}

	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !slices.Contains(validLogLevels, c.Logging.System.Level) {
		return Config{}, fmt.Errorf("invalid log level: %s", c.Logging.System.Level)
	}

	if c.Logging.System.Output == "" {
		return Config{}, errors.New("`output` is empty in logging config")
	}

	var backendConfig EncryptionBackend

	if c.EncryptionBackend == nil {
		return Config{}, errors.New("`encryption_backend` config is missing, it must be a map with backends, empty map means no encryption")
	}

	if len(c.EncryptionBackend) == 0 {
		backendConfig = EncryptionBackend{Type: None}
	} else {
		// For now we just take the first backend in the map.
		var firstBackend NamedBackendConfigYaml
		for _, v := range c.EncryptionBackend {
			firstBackend = v
			break
		}

		switch {
		case firstBackend.Vault != nil:
			if firstBackend.Vault.Endpoint == "" {
				return Config{}, errors.New("endpoint is missing")
			}
			if firstBackend.Vault.Mount == "" {
				return Config{}, errors.New("mount is missing")
			}
			if firstBackend.Vault.KeyName == "" {
				return Config{}, errors.New("key_name is missing")
			}
			if (firstBackend.Vault.AppRoleID == "" || firstBackend.Vault.AppRoleSecretID == "") && firstBackend.Vault.Token == "" {
				return Config{}, errors.New("either approle_role_id and approle_secret_id or token must be provided")
			}
			if (firstBackend.Vault.AppRoleID != "" || firstBackend.Vault.AppRoleSecretID != "") && firstBackend.Vault.Token != "" {
				return Config{}, errors.New("provide either approle_role_id and approle_secret_id or token, not both")
			}
			backendConfig = EncryptionBackend{
				Type:  Vault,
				Vault: firstBackend.Vault,
			}
		case firstBackend.PKCS11 != nil:
			if firstBackend.PKCS11.LibPath == "" {
				return Config{}, errors.New("lib_path is missing")
			}
			if firstBackend.PKCS11.Pin == "" {
				return Config{}, errors.New("pin is missing")
			}
			if firstBackend.PKCS11.KeyID == nil {
				return Config{}, errors.New("aes_encryption_key_id is missing")
			}
			backendConfig = EncryptionBackend{
				Type:   PKCS11,
				PKCS11: firstBackend.PKCS11,
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

// PublicConfigData contains non-sensitive configuration fields that are safe to expose
type PublicConfigData struct {
	Port                  int
	PebbleNotifications   bool
	LoggingLevel          string
	LoggingOutput         string
	EncryptionBackendType string
}

// PublicConfig returns the non-sensitive configuration fields that are safe to expose via API
func (c *Config) PublicConfig() PublicConfigData {
	return PublicConfigData{
		Port:                  c.Port,
		PebbleNotifications:   c.PebbleNotificationsEnabled,
		LoggingLevel:          string(c.Logging.System.Level),
		LoggingOutput:         c.Logging.System.Output,
		EncryptionBackendType: string(c.EncryptionBackend.Type),
	}
}
