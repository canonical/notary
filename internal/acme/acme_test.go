package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestResolveEnvironmentConfig(t *testing.T) {
	values := map[string]string{
		"CF_DNS_API_TOKEN":                 "provider-secret",
		eabKIDEnv:                          "account-key-id",
		eabHMACEnv:                         "base64url-hmac",
		"NOTARY_ACME_DNS_PROPAGATION_WAIT": "45",
		"NOTARY_ACME_DNS_NAMESERVERS":      "8.8.8.8:53, 1.1.1.1",
		disableCNAMEEnv:                    "true",
	}

	config, envVars, err := resolveEnvironmentConfig(values)
	if err != nil {
		t.Fatalf("resolveEnvironmentConfig() unexpected error: %v", err)
	}
	if config.eabKID != values[eabKIDEnv] || config.eabHMAC != values[eabHMACEnv] {
		t.Fatal("EAB credentials were not resolved")
	}
	if config.dnsPropagationWait != 45*time.Second {
		t.Fatalf("unexpected propagation wait: %s", config.dnsPropagationWait)
	}
	if len(config.dnsNameservers) != 2 ||
		config.dnsNameservers[0] != "8.8.8.8:53" ||
		config.dnsNameservers[1] != "1.1.1.1" {
		t.Fatalf("unexpected nameservers: %v", config.dnsNameservers)
	}
	if envVars["CF_DNS_API_TOKEN"] != "provider-secret" {
		t.Fatal("provider credential was removed")
	}
	if envVars[legoDisableCNAMEEnv] != "true" {
		t.Fatal("LEGO CNAME setting was removed")
	}
	for _, key := range []string{eabKIDEnv, eabHMACEnv, dnsPropagationWaitEnv, dnsNameserversEnv, disableCNAMEEnv} {
		if _, ok := envVars[key]; ok {
			t.Fatalf("internal setting %q was passed to the provider", key)
		}
	}
	if values[eabKIDEnv] == "" {
		t.Fatal("input map was mutated")
	}
}

func TestResolveEnvironmentConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
	}{
		{"incomplete EAB", map[string]string{eabKIDEnv: "kid"}},
		{"zero propagation wait", map[string]string{dnsPropagationWaitEnv: "0"}},
		{"invalid propagation wait", map[string]string{dnsPropagationWaitEnv: "later"}},
		{"empty nameserver entry", map[string]string{dnsNameserversEnv: "8.8.8.8,"}},
		{"hostname nameserver", map[string]string{dnsNameserversEnv: "dns.example.com"}},
		{"invalid CNAME boolean", map[string]string{disableCNAMEEnv: "sometimes"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := resolveEnvironmentConfig(test.values); err == nil {
				t.Fatal("resolveEnvironmentConfig() unexpectedly succeeded")
			}
		})
	}
}

func TestConfigureCABundle(t *testing.T) {
	envVars := map[string]string{}
	certificate := testCACertificate(t)

	cleanup, err := configureCABundle(envVars, certificate)
	if err != nil {
		t.Fatalf("configureCABundle() unexpected error: %v", err)
	}
	path := envVars[legoCACertificatesEnv]
	if path == "" {
		t.Fatal("LEGO CA certificate path was not configured")
	}
	if envVars[legoCASystemPoolEnv] != "true" {
		t.Fatal("system trust pool was not enabled")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temporary CA bundle: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary CA bundle permissions are %o, want 600", info.Mode().Perm())
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup temporary CA bundle: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary CA bundle still exists: %v", err)
	}

	if _, err := configureCABundle(map[string]string{}, "not PEM"); err == nil {
		t.Fatal("invalid PEM bundle was accepted")
	}
}

func TestSetEnvironmentRestoresValues(t *testing.T) {
	const existingKey = "NOTARY_ACME_EXISTING"
	const newKey = "NOTARY_ACME_NEW"
	t.Setenv(existingKey, "before")
	_ = os.Unsetenv(newKey)

	restore, err := setEnvironment(map[string]string{
		existingKey: "during",
		newKey:      "temporary",
	})
	if err != nil {
		t.Fatalf("setEnvironment() unexpected error: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore environment: %v", err)
	}
	if value := os.Getenv(existingKey); value != "before" {
		t.Fatalf("existing value was not restored: got %q", value)
	}
	if _, ok := os.LookupEnv(newKey); ok {
		t.Fatal("new environment variable was not removed")
	}
}

func testCACertificate(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Notary test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
