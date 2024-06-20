package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type ConfigYAML struct {
	KeyPath                    string `yaml:"key_path"`
	CertPath                   string `yaml:"cert_path"`
	DBPath                     string `yaml:"db_path"`
	Port                       int    `yaml:"port"`
	Pebblenotificationsenabled bool   `yaml:"pebble_notifications"`
}

type Config struct {
	Key                        []byte
	Cert                       []byte
	DBPath                     string
	Port                       int
	PebbleNotificationsEnabled bool
}

// Validate opens and processes the given yaml file, and catches errors in the process
func Validate(filePath string) (Config, error) {
	validationErr := errors.New("config file validation failed: ")
	config := Config{}
	configYaml, err := os.ReadFile(filePath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	c := ConfigYAML{}
	if err := yaml.Unmarshal(configYaml, &c); err != nil {
		return config, errors.Join(validationErr, err)
	}
	if c.CertPath == "" {
		return config, errors.Join(validationErr, errors.New("`cert_path` is empty"))
	}
	cert, err := os.ReadFile(c.CertPath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	if c.KeyPath == "" {
		return config, errors.Join(validationErr, errors.New("`key_path` is empty"))
	}
	key, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	if c.DBPath == "" {
		return config, errors.Join(validationErr, errors.New("`db_path` is empty"))
	}
	dbfile, err := os.OpenFile(c.DBPath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	err = dbfile.Close()
	if err != nil {
		return config, errors.Join(validationErr, err)
	}
	if c.Port == 0 {
		return config, errors.Join(validationErr, errors.New("`port` is empty"))
	}

	config.Cert = cert
	config.Key = key
	config.DBPath = c.DBPath
	config.Port = c.Port
	config.PebbleNotificationsEnabled = c.Pebblenotificationsenabled
	return config, nil
}
