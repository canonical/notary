package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/canonical/notary/internal/backend"
	"gopkg.in/yaml.v3"
)

type BackendType string

const (
	Vault  BackendType = "vault"
	PKCS11 BackendType = "pkcs11"
	None   BackendType = "none"
)

// VaultBackendConfig extends BackendConfig for Vault-specific fields.
type VaultBackendConfigYaml struct {
	Endpoint     string `yaml:"endpoint"`
	Mount        string `yaml:"mount"`
	KeyName      string `yaml:"key_name"`
	RoleID       string `yaml:"role_id"`
	RoleSecretID string `yaml:"role_secret_id"`
	Token        string `yaml:"token"`
}

// PKCS11BackendConfig extends BackendConfig for PKCS11-specific fields.
type PKCS11BackendConfigYaml struct {
	Endpoint string `yaml:"endpoint"`
	Slot     string `yaml:"slot"`
	PIN      string `yaml:"pin"`
}

type NoneBackendConfigYaml struct {
}

type EncryptionBackendConfigYaml struct {
	EncryptionBackend map[string]any `yaml:"encryption_backend"`
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

type Config struct {
	Key                        []byte
	Cert                       []byte
	ExternalHostname           string
	DBPath                     string
	Port                       int
	PebbleNotificationsEnabled bool
	Logging                    Logging
	EncryptionBackend          backend.EncryptionBackend
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

	config.Cert = cert
	config.Key = key
	config.ExternalHostname = c.ExternalHostname
	config.DBPath = c.DBPath
	config.Port = c.Port
	config.PebbleNotificationsEnabled = c.PebbleNotifications
	config.Logging.System.Level = LoggingLevel(c.Logging.System.Level)
	config.Logging.System.Output = c.Logging.System.Output

	config.EncryptionBackend, err = createEncryptionBackend(c.EncryptionBackend)
	if err != nil {
		return Config{}, fmt.Errorf("failed to create encryption backend: %w", err)
	}
	return config, nil
}

// createEncryptionBackend creates a SecretBackend based on the type specified
// in the config YAML.
func createEncryptionBackend(backendConfigYaml EncryptionBackendConfigYaml) (backend.EncryptionBackend, error) {
	// TODO: Should config depend on the backend package? If we're just passing back the config,
	// why are we converting the YAML to another struct?
	// We could just return the YAML and convert it later as necessary.
	backendType := BackendType(backendConfigYaml.EncryptionBackend["type"].(string))
	temp, err := yaml.Marshal(&backendConfigYaml.EncryptionBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault config: %w", err)
	}

	switch backendType {
	case Vault:
		vaultConfig := VaultBackendConfigYaml{} // something that implements SecretBAckend
		if err := yaml.Unmarshal(temp, &vaultConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vault config: %w", err)
		}

		if vaultConfig.Token != "" {
			return backend.NewVaultTokenBackend(vaultConfig.Endpoint, vaultConfig.Mount, vaultConfig.KeyName, vaultConfig.Token)
		} else if vaultConfig.RoleID != "" && vaultConfig.RoleSecretID != "" {
			return backend.NewVaultRoleBackend(vaultConfig.Endpoint, vaultConfig.Mount, vaultConfig.KeyName, vaultConfig.RoleID, vaultConfig.RoleSecretID)
		} else {
			return nil, fmt.Errorf("vault backend requires either a token or role_id and role_secret_id")
		}

	case PKCS11:
		pkcs11Config := PKCS11BackendConfigYaml{}
		if err := yaml.Unmarshal(temp, &pkcs11Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal pkcs11 config: %w", err)
		}
		return backend.PKCS11{
			Endpoint: pkcs11Config.Endpoint,
			Slot:     pkcs11Config.Slot,
			PIN:      pkcs11Config.PIN,
		}, nil

	case None:
		return backend.None{}, nil
	default:
		return backend.None{}, fmt.Errorf("unknown backend type: %s", backendType)
	}

}
