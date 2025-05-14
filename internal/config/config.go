package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"gopkg.in/yaml.v3"
)

type SystemLoggingConfigYaml struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type LoggingConfigYaml struct {
	System SystemLoggingConfigYaml `yaml:"system"`
}

type TracingConfigYaml struct {
	Enabled      bool   `yaml:"enabled"`
	ServiceName  string `yaml:"service_name"`
	TempoURL     string `yaml:"tempo_url"`
	SamplingRate string `yaml:"sampling_rate"`
}

type ConfigYAML struct {
	KeyPath             string            `yaml:"key_path"`
	CertPath            string            `yaml:"cert_path"`
	ExternalHostname    string            `yaml:"external_hostname"`
	DBPath              string            `yaml:"db_path"`
	Port                int               `yaml:"port"`
	PebbleNotifications bool              `yaml:"pebble_notifications"`
	Logging             LoggingConfigYaml `yaml:"logging"`
	Tracing             TracingConfigYaml `yaml:"tracing"`
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

type Tracing struct {
	Enabled      bool
	ServiceName  string
	TempoURL     string
	SamplingRate float64
}

type Config struct {
	Key                        []byte
	Cert                       []byte
	ExternalHostname           string
	DBPath                     string
	Port                       int
	PebbleNotificationsEnabled bool
	Logging                    Logging
	Tracing                    Tracing
}

// Validate opens and processes the given yaml file, and catches errors in the process
// parseSamplingRate converts a string sampling rate (percentage or decimal) to a float64
func parseSamplingRate(rate string) (float64, error) {
	// Try to parse as a float first
	samplingRate, err := strconv.ParseFloat(rate, 64)
	if err == nil {
		// Check if the value is between 0 and 1 inclusive
		if samplingRate < 0 || samplingRate > 1 {
			return 0, fmt.Errorf("sampling rate must be between 0 and 1, got %f", samplingRate)
		}
		return samplingRate, nil
	}
	
	// If parsing as float failed, check if it's a percentage string
	if len(rate) > 1 && rate[len(rate)-1] == '%' {
		// Remove % and parse as float
		percentage, err := strconv.ParseFloat(rate[:len(rate)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid sampling rate format: %s", rate)
		}
		
		// Convert percentage to decimal
		samplingRate = percentage / 100.0
		
		// Check if the value is between 0 and 1 inclusive
		if samplingRate < 0 || samplingRate > 1 {
			return 0, fmt.Errorf("sampling rate percentage must be between 0%% and 100%%, got %s", rate)
		}
		
		return samplingRate, nil
	}
	
	return 0, fmt.Errorf("invalid sampling rate format: %s", rate)
}

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

	// Set tracing defaults if not provided
	if c.Tracing.ServiceName == "" {
		c.Tracing.ServiceName = "notary"
	}

	// Default sampling rate to 1.0 (100%) if not specified
	samplingRate := 1.0
	if c.Tracing.SamplingRate != "" {
		var err error
		samplingRate, err = parseSamplingRate(c.Tracing.SamplingRate)
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
	config.Logging.System.Output = c.Logging.System.Output
	config.Tracing.Enabled = c.Tracing.Enabled
	config.Tracing.ServiceName = c.Tracing.ServiceName
	config.Tracing.TempoURL = c.Tracing.TempoURL
	config.Tracing.SamplingRate = samplingRate
	return config, nil
}
