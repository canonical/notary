package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

type SystemLoggingConfigYaml struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
	Path   string `yaml:"path"`
}

type LoggingConfigYaml struct {
	System SystemLoggingConfigYaml `yaml:"system"`
}

type ConfigYAML struct {
	KeyPath             string            `yaml:"key_path"`
	CertPath            string            `yaml:"cert_path"`
	ExternalHostname    string            `yaml:"external_hostname"`
	DBPath              string            `yaml:"db_path"`
	Port                int               `yaml:"port"`
	PebbleNotifications bool              `yaml:"pebble_notifications"`
	Logging             LoggingConfigYaml `yaml:"logging"`
}

type LoggingOutputType string

const (
	Stdout LoggingOutputType = "stdout"
	File   LoggingOutputType = "file"
)

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
	Output LoggingOutputType
	Path   string
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

	// Output Options are stdout and file.
	if c.Logging.System.Output == "" {
		return Config{}, fmt.Errorf("`output` is empty in logging config")
	}
	validOutputs := []string{"stdout", "file"}
	valid = false
	for _, output := range validOutputs {
		if c.Logging.System.Output == output {
			valid = true
			break
		}
	}

	if !valid {
		return Config{}, fmt.Errorf("invalid output: %s", c.Logging.System.Output)
	}
	if c.Logging.System.Output == "file" && c.Logging.System.Path == "" {
		return Config{}, fmt.Errorf("`path` is empty in logging config")
	}

	if c.Logging.System.Output == "file" {
		logFile, err := os.OpenFile(c.Logging.System.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return Config{}, err
		}
		err = logFile.Close()
		if err != nil {
			return Config{}, err
		}
	}

	config.Cert = cert
	config.Key = key
	config.ExternalHostname = c.ExternalHostname
	config.DBPath = c.DBPath
	config.Port = c.Port
	config.PebbleNotificationsEnabled = c.PebbleNotifications
	config.Logging.System.Level = LoggingLevel(c.Logging.System.Level)
	config.Logging.System.Output = LoggingOutputType(c.Logging.System.Output)
	config.Logging.System.Path = c.Logging.System.Path
	return config, nil
}
