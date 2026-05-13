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
	"sync"

	"github.com/canonical/notary/internal/db"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	legoconfig "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMERepository manages ACME account lifecycle and certificate issuance.
type ACMERepository struct {
	Email        string
	DirectoryURL string
	DNSProvider  string
	db           *db.DatabaseRepository
	mu           sync.Mutex
	user         *acmeUser
}

// NewACMERepository creates a new ACMERepository with the provided configuration.
func NewACMERepository(email, directoryURL, dnsProvider string, database *db.DatabaseRepository) (*ACMERepository, error) {
	if email == "" || directoryURL == "" || dnsProvider == "" {
		return nil, errors.New("acme: email, directory_url, and dns_provider are all required")
	}
	return &ACMERepository{
		Email:        email,
		DirectoryURL: directoryURL,
		DNSProvider:  dnsProvider,
		db:           database,
	}, nil
}

// loadOrCreateAccount loads the ACME account from the database or registers a new one.
// Must be called with r.mu held.
func (r *ACMERepository) loadOrCreateAccount() error {
	if r.user != nil {
		return nil
	}

	exists, err := r.db.ACMEAccountExists()
	if err != nil {
		return fmt.Errorf("failed to check ACME account existence: %w", err)
	}

	if !exists {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ACME account key: %w", err)
		}

		user := &acmeUser{email: r.Email, key: privKey}

		cfg := legoconfig.NewConfig(user)
		cfg.CADirURL = r.DirectoryURL
		cfg.Certificate.KeyType = certcrypto.EC256

		client, err := legoconfig.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create ACME client: %w", err)
		}

		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.registration = reg

		keyDER, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			return fmt.Errorf("failed to marshal ACME account key: %w", err)
		}
		privKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

		regBodyJSON, err := json.Marshal(reg)
		if err != nil {
			return fmt.Errorf("failed to marshal ACME registration: %w", err)
		}

		if err := r.db.CreateACMEAccount(r.Email, privKeyPEM, reg.URI, string(regBodyJSON)); err != nil {
			return fmt.Errorf("failed to store ACME account: %w", err)
		}

		r.user = user
		return nil
	}

	account, err := r.db.GetDecryptedACMEAccount()
	if err != nil {
		return fmt.Errorf("failed to load ACME account: %w", err)
	}

	block, _ := pem.Decode([]byte(account.PrivateKeyPEM))
	if block == nil {
		return errors.New("failed to decode ACME account private key PEM")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse ACME account private key: %w", err)
	}

	var reg registration.Resource
	if err := json.Unmarshal([]byte(account.RegistrationBody), &reg); err != nil {
		return fmt.Errorf("failed to unmarshal ACME registration: %w", err)
	}

	r.user = &acmeUser{
		email:        account.Email,
		registration: &reg,
		key:          privKey,
	}
	return nil
}

// SignCSR uses the ACME protocol with DNS-01 challenge to obtain a signed certificate for the given CSR.
func (r *ACMERepository) SignCSR(csrPEM string) (string, error) {
	r.mu.Lock()
	if err := r.loadOrCreateAccount(); err != nil {
		r.mu.Unlock()
		return "", fmt.Errorf("acme: failed to initialize account: %w", err)
	}
	user := r.user
	r.mu.Unlock()

	cfg := legoconfig.NewConfig(user)
	cfg.CADirURL = r.DirectoryURL
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := legoconfig.NewClient(cfg)
	if err != nil {
		return "", fmt.Errorf("acme: failed to create ACME client: %w", err)
	}

	provider, err := dns.NewDNSChallengeProviderByName(r.DNSProvider)
	if err != nil {
		return "", fmt.Errorf("acme: unknown DNS provider %q: %w", r.DNSProvider, err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
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
