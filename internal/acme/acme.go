package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	legoconfig "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	mdns "github.com/miekg/dns"
)

const (
	eabKIDEnv             = "NOTARY_ACME_EAB_KID"
	eabHMACEnv            = "NOTARY_ACME_EAB_HMAC"
	acmeCACertificatesEnv = "NOTARY_ACME_CA_CERTIFICATES"
	dnsPropagationWaitEnv = "NOTARY_ACME_DNS_PROPAGATION_WAIT"
	dnsNameserversEnv     = "NOTARY_ACME_DNS_NAMESERVERS"
	disableCNAMEEnv       = "NOTARY_ACME_DISABLE_CNAME_SUPPORT"
	legoCACertificatesEnv = "LEGO_CA_CERTIFICATES"
	legoCASystemPoolEnv   = "LEGO_CA_SYSTEM_CERT_POOL"
	legoDisableCNAMEEnv   = "LEGO_DISABLE_CNAME_SUPPORT"
)

var (
	signingMu                   sync.Mutex
	defaultRecursiveNameservers = systemNameservers()
)

type operationConfig struct {
	eabKID             string
	eabHMAC            string
	acmeCACertificates string
	dnsPropagationWait time.Duration
	dnsNameservers     []string
}

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMERepository holds everything needed to obtain a certificate from an ACME
// server for a single signing operation.
type ACMERepository struct {
	serverID     int64
	email        string
	directoryURL string
	dnsProvider  string
	envVars      map[string]string
	db           *db.DatabaseRepository
}

func NewACMERepository(serverID int64, email, directoryURL, dnsProvider string, envVars map[string]string, database *db.DatabaseRepository) *ACMERepository {
	return &ACMERepository{
		serverID:     serverID,
		email:        email,
		directoryURL: directoryURL,
		dnsProvider:  dnsProvider,
		envVars:      envVars,
		db:           database,
	}
}

// loadOrCreateAccount returns an acmeUser backed by a DB-persisted account.
// Must be called with signingMu held.
func (r *ACMERepository) loadOrCreateAccount(config operationConfig) (*acmeUser, error) {
	account, err := r.db.GetACMEAccountByEmailAndURL(r.email, r.directoryURL)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, fmt.Errorf("failed to look up ACME account: %w", err)
	}

	if err == nil {
		block, _ := pem.Decode([]byte(account.PrivateKeyPEM))
		if block == nil {
			return nil, errors.New("failed to decode ACME account private key PEM")
		}
		privKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ACME account private key: %w", err)
		}
		var reg registration.Resource
		if err := json.Unmarshal([]byte(account.RegistrationBody), &reg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ACME registration: %w", err)
		}
		return &acmeUser{
			email:        account.Email,
			registration: &reg,
			key:          privKey,
		}, nil
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ACME account key: %w", err)
	}

	user := &acmeUser{email: r.email, key: privKey}

	cfg := legoconfig.NewConfig(user)
	cfg.CADirURL = r.directoryURL
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := legoconfig.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	var reg *registration.Resource
	if config.eabKID != "" {
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  config.eabKID,
			HmacEncoded:          config.eabHMAC,
		})
	} else {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to register ACME account: %w", err)
	}
	user.registration = reg

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ACME account key: %w", err)
	}
	privKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	regBodyJSON, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ACME registration: %w", err)
	}

	newAccount, err := r.db.GetOrCreateACMEAccount(r.email, r.directoryURL, privKeyPEM, reg.URI, string(regBodyJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to store ACME account: %w", err)
	}

	if r.serverID > 0 {
		if err := r.db.LinkAccountToServer(r.serverID, newAccount.ID); err != nil {
			return nil, fmt.Errorf("failed to link ACME account to server: %w", err)
		}
	}

	return user, nil
}

// SignCSR obtains a signed certificate via ACME DNS-01 challenge.
// Env vars are injected into the process environment under signingMu.
func (r *ACMERepository) SignCSR(csrPEM string) (certificatePEM string, returnErr error) {
	signingMu.Lock()
	defer signingMu.Unlock()

	config, envVars, err := resolveEnvironmentConfig(r.envVars)
	if err != nil {
		return "", fmt.Errorf("acme: invalid configuration: %w", err)
	}

	cleanupCA, err := configureCABundle(envVars, config.acmeCACertificates)
	if err != nil {
		return "", fmt.Errorf("acme: invalid CA certificates: %w", err)
	}
	defer func() {
		if err := cleanupCA(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("acme: failed to clean up CA certificates: %w", err))
		}
	}()

	restoreEnvironment, err := setEnvironment(envVars)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := restoreEnvironment(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("acme: failed to restore environment: %w", err))
		}
	}()

	user, err := r.loadOrCreateAccount(config)
	if err != nil {
		return "", fmt.Errorf("acme: failed to initialize account: %w", err)
	}

	cfg := legoconfig.NewConfig(user)
	cfg.CADirURL = r.directoryURL
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := legoconfig.NewClient(cfg)
	if err != nil {
		return "", fmt.Errorf("acme: failed to create ACME client: %w", err)
	}

	provider, err := dns.NewDNSChallengeProviderByName(strings.ToLower(r.dnsProvider))
	if err != nil {
		return "", fmt.Errorf("acme: unknown DNS provider %q: %w", r.dnsProvider, err)
	}
	var challengeOptions []dns01.ChallengeOption
	if config.dnsPropagationWait > 0 {
		challengeOptions = append(challengeOptions, dns01.PropagationWait(config.dnsPropagationWait, true))
	}
	if len(config.dnsNameservers) > 0 {
		challengeOptions = append(challengeOptions, dns01.AddRecursiveNameservers(config.dnsNameservers))
		defer func() {
			_ = dns01.AddRecursiveNameservers(defaultRecursiveNameservers)(nil)
		}()
	}
	if err := client.Challenge.SetDNS01Provider(provider, challengeOptions...); err != nil {
		return "", fmt.Errorf("acme: failed to set DNS-01 provider: %w", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", errors.New("acme: failed to decode CSR PEM")
	}
	x509CSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("acme: failed to parse CSR: %w", err)
	}

	resource, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:    x509CSR,
		Bundle: true,
	})
	if err != nil {
		return "", fmt.Errorf("acme: certificate issuance failed: %w", err)
	}

	return string(resource.Certificate), nil
}

func resolveEnvironmentConfig(values map[string]string) (operationConfig, map[string]string, error) {
	envVars := make(map[string]string, len(values)+2)
	for key, value := range values {
		envVars[key] = value
	}

	config := operationConfig{
		eabKID:             strings.TrimSpace(envVars[eabKIDEnv]),
		eabHMAC:            strings.TrimSpace(envVars[eabHMACEnv]),
		acmeCACertificates: strings.TrimSpace(envVars[acmeCACertificatesEnv]),
	}
	for _, key := range []string{
		eabKIDEnv,
		eabHMACEnv,
		acmeCACertificatesEnv,
		dnsPropagationWaitEnv,
		dnsNameserversEnv,
		disableCNAMEEnv,
	} {
		delete(envVars, key)
	}

	if (config.eabKID == "") != (config.eabHMAC == "") {
		return operationConfig{}, nil, fmt.Errorf("%s and %s must be set together", eabKIDEnv, eabHMACEnv)
	}

	if value := strings.TrimSpace(values[dnsPropagationWaitEnv]); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds <= 0 {
			return operationConfig{}, nil, fmt.Errorf("%s must be a positive integer", dnsPropagationWaitEnv)
		}
		config.dnsPropagationWait = time.Duration(seconds) * time.Second
	}

	if value := strings.TrimSpace(values[dnsNameserversEnv]); value != "" {
		nameservers, err := parseNameservers(value)
		if err != nil {
			return operationConfig{}, nil, fmt.Errorf("%s: %w", dnsNameserversEnv, err)
		}
		config.dnsNameservers = nameservers
	}

	if value := strings.TrimSpace(values[disableCNAMEEnv]); value != "" {
		disableCNAME, err := strconv.ParseBool(value)
		if err != nil {
			return operationConfig{}, nil, fmt.Errorf("%s must be a boolean", disableCNAMEEnv)
		}
		envVars[legoDisableCNAMEEnv] = strconv.FormatBool(disableCNAME)
	}

	return config, envVars, nil
}

func parseNameservers(value string) ([]string, error) {
	var nameservers []string
	for _, value := range strings.Split(value, ",") {
		nameserver := strings.TrimSpace(value)
		if nameserver == "" {
			return nil, errors.New("cannot contain empty entries")
		}
		if net.ParseIP(nameserver) == nil {
			host, port, err := net.SplitHostPort(nameserver)
			if err != nil || net.ParseIP(host) == nil {
				return nil, fmt.Errorf("%q must be an IP address with an optional port", nameserver)
			}
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return nil, fmt.Errorf("%q has an invalid port", nameserver)
			}
		}
		nameservers = append(nameservers, nameserver)
	}
	return nameservers, nil
}

func configureCABundle(envVars map[string]string, certificates string) (func() error, error) {
	if certificates == "" {
		return func() error { return nil }, nil
	}
	if err := validateCertificateBundle(certificates); err != nil {
		return nil, err
	}

	file, err := os.CreateTemp("", "notary-acme-ca-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create temporary CA bundle: %w", err)
	}
	path := file.Name()
	cleanup := func() error {
		return os.Remove(path)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = cleanup()
		return nil, fmt.Errorf("secure temporary CA bundle: %w", err)
	}
	if _, err := file.WriteString(certificates); err != nil {
		_ = file.Close()
		_ = cleanup()
		return nil, fmt.Errorf("write temporary CA bundle: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("close temporary CA bundle: %w", err)
	}

	envVars[legoCACertificatesEnv] = path
	envVars[legoCASystemPoolEnv] = "true"
	return cleanup, nil
}

func validateCertificateBundle(certificates string) error {
	remaining := []byte(certificates)
	count := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("contains invalid PEM data")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("contains PEM block %q, expected CERTIFICATE", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate %d: %w", count+1, err)
		}
		if !certificate.IsCA {
			return fmt.Errorf("certificate %d is not a CA certificate", count+1)
		}
		count++
		remaining = rest
	}
	if count == 0 {
		return errors.New("contains no certificates")
	}
	return nil
}

func setEnvironment(values map[string]string) (func() error, error) {
	saved := make(map[string]*string, len(values))
	restore := func() error {
		var restoreErr error
		for key, previous := range saved {
			if previous == nil {
				if err := os.Unsetenv(key); err != nil {
					restoreErr = errors.Join(restoreErr, fmt.Errorf("unset %q: %w", key, err))
				}
			} else if err := os.Setenv(key, *previous); err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("restore %q: %w", key, err))
			}
		}
		return restoreErr
	}

	for key, value := range values {
		if previous, ok := os.LookupEnv(key); ok {
			saved[key] = &previous
		} else {
			saved[key] = nil
		}
		if err := os.Setenv(key, value); err != nil {
			return nil, errors.Join(fmt.Errorf("acme: invalid env var key %q: %w", key, err), restore())
		}
	}
	return restore, nil
}

func systemNameservers() []string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return []string{
			"google-public-dns-a.google.com:53",
			"google-public-dns-b.google.com:53",
		}
	}
	nameservers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		nameservers = append(nameservers, server)
	}
	return nameservers
}
