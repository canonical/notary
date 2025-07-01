package config_test

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/config"
	"github.com/google/go-cmp/cmp"
)

func TestValidConfig(t *testing.T) {
	mustPrepareCertificateFiles(t)

	cases := []struct {
		desc       string
		configYAML string
		wantCfg    config.Config
	}{
		{"minimal config", validMinimalConfig, config.Config{
			Cert:                       []byte(validCert),
			Key:                        []byte(validPK),
			ExternalHostname:           "localhost",
			DBPath:                     "./notary.db",
			Port:                       8000,
			PebbleNotificationsEnabled: false,
			Logging: config.Logging{
				System: config.SystemLoggingConfig{
					Level:  "debug",
					Output: "stdout",
				},
			},
			EncryptionBackend: config.EncryptionBackend{
				Type:   config.None,
				PKCS11: nil,
				Vault:  nil,
			},
		}}, // This case tests the expected default values for missing fields are filled correctly
		{"full config", validFullConfig, config.Config{
			Cert:                       []byte(validCert),
			Key:                        []byte(validPK),
			ExternalHostname:           "example.com",
			DBPath:                     "./notary.db",
			Port:                       8000,
			PebbleNotificationsEnabled: false,
			Logging: config.Logging{
				System: config.SystemLoggingConfig{
					Level:  "info",
					Output: "some/file",
				},
			},
			EncryptionBackend: config.EncryptionBackend{
				Type: config.PKCS11,
				PKCS11: &config.PKCS11BackendConfigYaml{
					LibPath: "path/to/lib",
					KeyID:   func() *uint16 { v := uint16(16); return &v }(),
					Pin:     "0001password",
				},
			},
		}}, // This case tests that the variables from the yaml are correctly copied to the final config
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := os.WriteFile("config.yaml", []byte(tc.configYAML), 0o644)
			if err != nil {
				t.Errorf("Error writing config file")
			}
			gotCfg, err := config.ValidateConfig("config.yaml")
			if err != nil {
				t.Errorf("ValidateConfig(%q) = %v, want nil", "config.yaml", err)
			}
			if !cmp.Equal(gotCfg, tc.wantCfg) {
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
		{"no encryption backend", noEncryptionBackendConfig, "`encryption_backend` config is missing, it must be a map with backends, empty map means no encryption"},
		{"invalid pkcs11 encryption backend config", invalidEncryptionBackendConfigType, "invalid encryption backend type; must be 'vault' or 'pkcs11'"},
		{"incomplete pkcs11 encryption backend config", incompleteEncryptionBackendConfig, "pin is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := os.WriteFile("config.yaml", []byte(tc.configYAML), 0o644)
			if err != nil {
				t.Errorf("Failed writing config file: %v", err)
			}
			_, err = config.ValidateConfig("config.yaml")
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
encryption_backend: {}
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
  output: "some/file"
encryption_backend:
 yubihsm:
  pkcs11:
   lib_path: "path/to/lib"
   aes_encryption_key_id: 16
   pin: "0001password"
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
encryption_backend: {}
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
encryption_backend: {}
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
encryption_backend: {}
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
encryption_backend: {}
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
encryption_backend: {}
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
encryption_backend: {}
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
  yubihsm2:
    invalid:
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
  yubihsm2:
    pkcs11:
      lib_path: "/usr/local/lib/pkcs11/yubihsm_pkcs11.so"
      aes_encryption_key_id: 0x1234
`
	invalidYAMLConfig = `just_an=invalid
yaml.here`
)
