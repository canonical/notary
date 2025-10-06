package config_test

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/canonical/notary/internal/encryption_backend"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/pflag"
)

func TestValidConfig(t *testing.T) {
	mustPrepareCertificateFiles(t)

	cases := []struct {
		desc       string
		configYAML string
		wantCfg    *config.NotaryAppContext
	}{
		{"minimal config", validMinimalConfig, &config.NotaryAppContext{
			PublicConfig: &config.PublicConfigData{
				Port:                  8000,
				LoggingLevel:          "debug",
				LoggingOutput:         "stdout",
				EncryptionBackendType: "none",
			},
			TLSCertificate:             []byte(validCert),
			TLSPrivateKey:              []byte(validPK),
			ExternalHostname:           "localhost",
			DBPath:                     "./notary.db",
			Port:                       8000,
			PebbleNotificationsEnabled: false,
            SystemLogger:               nil,
            AuditLogger:                nil,
			EncryptionBackend:          encryption_backend.NoEncryptionBackend{},
			EncryptionBackendType:      config.EncryptionBackendTypeNone,
		}}, // This case tests the expected default values for missing fields are filled correctly
		{"full config", validFullConfig, &config.NotaryAppContext{
			PublicConfig: &config.PublicConfigData{
				Port:                  8000,
				LoggingLevel:          "info",
				LoggingOutput:         "stdout",
				EncryptionBackendType: "none",
			},
			TLSCertificate:             []byte(validCert),
			TLSPrivateKey:              []byte(validPK),
			ExternalHostname:           "example.com",
			DBPath:                     "./notary.db",
			Port:                       8000,
			PebbleNotificationsEnabled: false,
            SystemLogger:               nil,
            AuditLogger:                nil,
			EncryptionBackend:          encryption_backend.NoEncryptionBackend{},
			EncryptionBackendType:      config.EncryptionBackendTypeNone,
		}}, // This case tests that the variables from the yaml are correctly copied to the final config
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := os.WriteFile("config.yaml", []byte(tc.configYAML), 0o644)
			if err != nil {
				t.Errorf("Error writing config file")
			}
			gotCfg, err := config.CreateAppContext(&pflag.FlagSet{}, "config.yaml")
			if err != nil {
				t.Errorf("ValidateConfig(%q) = %v, want nil", "config.yaml", err)
				return
			}
            if !cmp.Equal(gotCfg, tc.wantCfg, cmpopts.IgnoreFields(config.NotaryAppContext{}, "SystemLogger", "AuditLogger")) {
				t.Errorf("ValidateConfig returned unexpected diff (-want+got):\n%v", cmp.Diff(tc.wantCfg, gotCfg))
			}
		})
	}
}

func TestInvalidConfig(t *testing.T) {
	mustPrepareCertificateFiles(t)

	cases := []struct {
		desc       string
		configYAML string
		wantErr    string
	}{
		{"no cert path", noCertPathConfig, "`cert_path` is empty"},
		{"no key path", noKeyPathConfig, "`key_path` is empty"},
		{"no db path", noDBPathConfig, "`db_path` is empty"},
		{"wrong cert path", wrongCertPathConfig, "no such file or directory"},
		{"wrong key path", wrongKeyPathConfig, "no such file or directory"},
		{"invalid yaml", invalidYAMLConfig, "unmarshal errors"},
		{"no encryption backend", noEncryptionBackendConfig, "`encryption_backend` is empty"},
		{"invalid pkcs11 encryption backend config", invalidEncryptionBackendConfigType, "invalid encryption backend type; must be 'none', 'vault' or 'pkcs11'"},
		{"incomplete pkcs11 encryption backend config", incompleteEncryptionBackendConfig, "pin is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := os.WriteFile("config.yaml", []byte(tc.configYAML), 0o644)
			if err != nil {
				t.Errorf("Failed writing config file: %v", err)
			}
			_, err = config.CreateAppContext(&pflag.FlagSet{}, "config.yaml")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("config.Validate(%v) = %v, want %v", tc.configYAML, err, tc.wantErr)
			}
		})
	}
}

func mustPrepareCertificateFiles(t *testing.T) {
	t.Helper()
	testfolder := t.TempDir()
	err := os.WriteFile(testfolder+"/cert_test.pem", []byte(validCert), 0o644)
	if err != nil {
		log.Fatalf("couldn't create temp testing file: %v", err)
	}
	err = os.WriteFile(testfolder+"/key_test.pem", []byte(validPK), 0o644)
	if err != nil {
		log.Fatalf("couldn't create temp testing file: %v", err)
	}
	t.Chdir(testfolder)
}

const (
	validCert          = `----- CERTIFICATE -----...`
	validPK            = `----- PRIVATE KEY -----...`
	validMinimalConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
db_path: "./notary.db"
port: 8000
encryption_backend:
  type: "none"
`
	validFullConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
pebble_notifications: false
port: 8000
logging:
 system:
  level: "info"
  output: "stdout"
encryption_backend:
  type: "none"
`
)

const (
	noCertPathConfig = `
key_path:  "./key_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	noKeyPathConfig = `
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	noExternalHostnameConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	noDBPathConfig = `
key_path:  "./key_test.pem"
external_hostname: "example.com"
cert_path: "./cert_test.pem"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	wrongCertPathConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test_wrong.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	wrongKeyPathConfig = `
key_path:  "./key_test_wrong.pem"
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "none"
`
	invalidEncryptionBackendConfigType = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "invalid"
  lib_path: "/usr/local/lib/pkcs11/yubihsm_pkcs11.so"
  aes_encryption_key_id: 0x1234
  pin: "0001password"
`
	noEncryptionBackendConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
`
	incompleteEncryptionBackendConfig = `
key_path:  "./key_test.pem"
cert_path: "./cert_test.pem"
external_hostname: "example.com"
db_path: "./notary.db"
port: 8000
logging:
  system:
    level: "debug"
    output: "stdout"
encryption_backend:
  type: "pkcs11"
  lib_path: "/usr/local/lib/pkcs11/yubihsm_pkcs11.so"
  aes_encryption_key_id: 0x1234
`
	invalidYAMLConfig = `just_an=invalid
yaml.here`
)
