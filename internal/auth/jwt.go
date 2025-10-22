package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type ProviderType int

const (
	ProviderLocal ProviderType = iota
	ProviderOIDC
)

type ProviderConfig struct {
	Issuer    string
	ClientID  string // for OIDC
	JWKSURL   string // optional, manual JWKS override
	Type      ProviderType
	PublicKey *rsa.PublicKey // for local JWT verification
	Secret    []byte         // for HMAC local tokens (if used)
}

type Verifier struct {
	providers []ProviderConfig
}

func NewVerifier(providers []ProviderConfig) *Verifier {
	return &Verifier{providers: providers}
}

func (v *Verifier) VerifyToken(ctx context.Context, rawToken string) (map[string]interface{}, error) {
	var lastErr error

	for _, p := range v.providers {
		switch p.Type {
		case ProviderOIDC:
			idToken, err := verifyOIDCToken(ctx, p, rawToken)
			if err == nil {
				var claims map[string]interface{}
				if err := idToken.Claims(&claims); err != nil {
					return nil, err
				}
				return claims, nil
			}
			lastErr = err

		case ProviderLocal:
			claims, err := verifyLocalJWT(rawToken, p)
			if err == nil {
				return claims, nil
			}
			lastErr = err
		}
	}

	return nil, fmt.Errorf("no provider accepted token: %w", lastErr)
}

func verifyOIDCToken(ctx context.Context, p ProviderConfig, raw string) (*oidc.IDToken, error) {
	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})

	return verifier.Verify(ctx, raw)
}

func verifyLocalJWT(raw string, p ProviderConfig) (map[string]interface{}, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return p.Secret, nil
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
		}
	})
	if err != nil {
		return nil, fmt.Errorf("local token parse error: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid local token")
	}

	// token, err := jwt.ParseWithClaims(rawToken, &claims, func(token *jwt.Token) (interface{}, error) {
	// 	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	// 		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	// 	}
	// 	return jwtSecret, nil
	// })

	return claims, nil
}
