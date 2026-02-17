package authentication

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type NotaryJWTClaims struct {
	Permissions []string
	Email       string
	RoleID      int `json:"role_id"`
	jwt.RegisteredClaims
}

type localJWTClaims struct {
	Permissions []string `json:"permissions"`
	Email       string   `json:"email"`
	RoleID      int      `json:"role_id"`
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
}
