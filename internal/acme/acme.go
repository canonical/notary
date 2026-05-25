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
	"os"
	"strings"
	"sync"

	"github.com/canonical/notary/internal/db"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	legoconfig "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

var signingMu sync.Mutex

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
func (r *ACMERepository) loadOrCreateAccount() (*acmeUser, error) {
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

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
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
func (r *ACMERepository) SignCSR(csrPEM string) (string, error) {
	signingMu.Lock()

	saved := make(map[string]*string, len(r.envVars))
	for k, v := range r.envVars {
		if prev, ok := os.LookupEnv(k); ok {
			saved[k] = &prev
		} else {
			saved[k] = nil
		}
		if err := os.Setenv(k, v); err != nil {
			signingMu.Unlock()
			return "", fmt.Errorf("acme: invalid env var key %q: %w", k, err)
		}
	}
	defer func() {
		for k, prev := range saved {
			if prev != nil {
				os.Setenv(k, *prev) //nolint:errcheck
			} else {
				os.Unsetenv(k) //nolint:errcheck
			}
		}
		signingMu.Unlock()
	}()

	user, err := r.loadOrCreateAccount()
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
