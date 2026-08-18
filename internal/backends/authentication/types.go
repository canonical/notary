package authentication

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type NotaryJWTClaims struct {
	Email  string `json:"email"`
	RoleID int    `json:"role_id"`
	jwt.RegisteredClaims
}

type localJWTClaims struct {
	Email  string `json:"email"`
	RoleID int    `json:"role_id"`
	jwt.RegisteredClaims
}

type ProviderType int

const (
	ProviderLocal ProviderType = iota
	ProviderOIDC
)

type ProviderConfig struct {
	Type     ProviderType
	Provider *OIDCRepository // for OIDC key verification
	Secret   []byte          // for HMAC local tokens (if used)
}

type Verifier struct {
	providers []ProviderConfig
}

// Repository for the OIDC configuration
type OIDCRepository struct {
	// Name uniquely identifies this provider in configuration, in the login
	// provider selector, and in the /oauth/login?provider= query parameter.
	Name string
	// This is the OIDC configuration of the configured server
	OIDCProvider *oidc.Provider
	// This is the oauth2 configuration for the IDP
	OAuth2Config *oauth2.Config
	// The audience is the value that the IDP will use to identify the Notary server with the correct API scopes
	Audience string
	// The issuer identifier for the OIDC provider, captured from discovery
	Issuer string
	// This is the key for the email claim in the access token
	EmailClaimKey string
	// This is the key for the permissions claim in the access token
	PermissionsClaimKey string
	// This is the key function for verifying the access token coming from the IDP
	KeyFunc keyfunc.Keyfunc
	// RoleMapping maps a claim value to a Notary role for users provisioned
	// through this provider. It is defined in the config file, never in the
	// database, so it is identical on every node without a database read.
	RoleMapping RoleMapping
}

// RoleMapping resolves a Notary role from the claims of an OIDC identity token.
type RoleMapping struct {
	// Claim is the name of the claim holding the values to match against, e.g. "groups".
	Claim string
	// Values maps a claim value to the Notary role ID it grants. When a token
	// carries several matching values, the most privileged (lowest) role wins.
	Values map[string]int
}

// OIDCProviders is the set of OIDC providers configured on this node. Any number
// of providers may be configured simultaneously; user identity is keyed by
// (issuer, subject).
type OIDCProviders []*OIDCRepository

// Enabled reports whether any OIDC provider is configured.
func (p OIDCProviders) Enabled() bool {
	return len(p) > 0
}

// Get returns the provider with the given name. An empty name returns the first
// configured provider, which is what a single-provider deployment always wants.
func (p OIDCProviders) Get(name string) (*OIDCRepository, bool) {
	if len(p) == 0 {
		return nil, false
	}
	if name == "" {
		return p[0], true
	}
	for _, provider := range p {
		if provider.Name == name {
			return provider, true
		}
	}
	return nil, false
}

// ByIssuer returns the provider that declared the given issuer identifier.
func (p OIDCProviders) ByIssuer(issuer string) (*OIDCRepository, bool) {
	for _, provider := range p {
		if provider.Issuer == issuer {
			return provider, true
		}
	}
	return nil, false
}

// Names returns the configured provider names, in configuration order.
func (p OIDCProviders) Names() []string {
	names := make([]string, 0, len(p))
	for _, provider := range p {
		names = append(names, provider.Name)
	}
	return names
}
