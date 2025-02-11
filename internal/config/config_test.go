package config_test

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/config"
)

const (
	validCert   = `Whatever cert content`
	validPK     = `Whatever key content`
	validConfig = `key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
db_path: "./certs.db"
port: 8000`
	noCertPathConfig = `key_path:  "./key_test.pem"
db_path: "./certs.db"
port: 8000`
	noKeyPathConfig = `cert_path: "./cert_test.pem"
db_path: "./certs.db"
port: 8000`
	noDBPathConfig = `key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
port: 8000`
	wrongCertPathConfig = `key_path:  "./key_test.pem"
cert_path: "./cert_test_wrong.pem"
db_path: "./certs.db"
port: 8000`
	wrongKeyPathConfig = `key_path:  "./key_test_wrong.pem"
cert_path: "./cert_test.pem"
db_path: "./certs.db"
port: 8000`
	invalidYAMLConfig = `just_an=invalid
yaml.here`
)

func TestMain(m *testing.M) {
	testfolder, err := os.MkdirTemp("./", "configtest-")
	if err != nil {
		log.Fatalf("couldn't create temp directory: %s", err)
	}
	err = os.WriteFile(testfolder+"/cert_test.pem", []byte(validCert), 0o644)
	if err != nil {
		log.Fatalf("couldn't create temp testing file: %s", err)
	}
	err = os.WriteFile(testfolder+"/key_test.pem", []byte(validPK), 0o644)
	if err != nil {
		log.Fatalf("couldn't create temp testing file: %s", err)
	}
	if err := os.Chdir(testfolder); err != nil {
		log.Fatalf("couldn't enter testing directory: %s", err)
	}

	exitval := m.Run()

	if err := os.Chdir("../"); err != nil {
		log.Fatalf("couldn't change back to parent directory: %s", err)
	}
	if err := os.RemoveAll(testfolder); err != nil {
		log.Fatalf("couldn't remove temp testing directory: %s", err)
	}
	os.Exit(exitval)
}

func TestGoodConfigSuccess(t *testing.T) {
	writeConfigErr := os.WriteFile("config.yaml", []byte(validConfig), 0o644)
	if writeConfigErr != nil {
		t.Fatalf("Error writing config file")
	}
	conf, err := config.Validate("config.yaml")
	if err != nil {
		t.Fatalf("Error occurred: %s", err)
	}

	if conf.Cert == nil {
		t.Fatalf("No certificates were configured for server")
	}

	if conf.Key == nil {
		t.Fatalf("No key was configured for server")
	}

	if conf.DBPath == "" {
		t.Fatalf("No database path was configured for server")
	}

	if conf.Port != 8000 {
		t.Fatalf("Port was not configured correctly")
	}
}

func TestBadConfigFail(t *testing.T) {
	cases := []struct {
		Name          string
		ConfigYAML    string
		ExpectedError string
	}{
		{"no cert path", noCertPathConfig, "`cert_path` is empty"},
		{"no key path", noKeyPathConfig, "`key_path` is empty"},
		{"no db path", noDBPathConfig, "`db_path` is empty"},
		{"wrong cert path", wrongCertPathConfig, "no such file or directory"},
		{"wrong key path", wrongKeyPathConfig, "no such file or directory"},
		{"invalid yaml", invalidYAMLConfig, "unmarshal errors"},
	}

	for _, tc := range cases {
		err := os.WriteFile("config.yaml", []byte(tc.ConfigYAML), 0o644)
		if err != nil {
			t.Errorf("Failed writing config file: %v", err)
		}
		_, err = config.Validate("config.yaml")
		if err == nil {
			t.Errorf("Expected error, got nil")
		}

		if !strings.Contains(err.Error(), tc.ExpectedError) {
			t.Errorf("Expected error not found: %s", err)
		}
	}
}
