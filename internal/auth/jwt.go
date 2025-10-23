package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/canonical/notary/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

type ProviderType int

const (
	ProviderLocal ProviderType = iota
	ProviderOIDC
)

type ProviderConfig struct {
	Type     ProviderType
	Provider *config.OIDCConfig // for OIDC key verification
	Secret   []byte             // for HMAC local tokens (if used)
}

type Verifier struct {
	providers []ProviderConfig
}

func NewVerifier(providers []ProviderConfig) *Verifier {
	return &Verifier{providers: providers}
}

func (v *Verifier) VerifyToken(ctx context.Context, rawToken string) (*NotaryJWTClaims, error) {
	errors := make([]error, 0, 2)

	for _, p := range v.providers {
		switch p.Type {
		case ProviderOIDC:
			claims, err := verifyOIDCAccessToken(ctx, p, rawToken)
			if err == nil {
				return claims, nil
			}
			errors = append(errors, fmt.Errorf("oidc: %w", err))

		case ProviderLocal:
			claims, err := verifyLocalJWT(ctx, p, rawToken)
			if err == nil {
				return claims, nil
			}
			errors = append(errors, fmt.Errorf("local: %w", err))
		}
	}

	return nil, fmt.Errorf("no provider accepted token: %s", fmt.Sprint(errors))
}

func verifyOIDCAccessToken(ctx context.Context, p ProviderConfig, raw string) (*NotaryJWTClaims, error) {
	if p.Provider == nil {
		return nil, fmt.Errorf("provider is nil")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, &claims, p.Provider.KeyFunc.KeyfuncCtx(ctx))
	if err != nil {
		return nil, fmt.Errorf("oidc parsing token failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("oidc token is not valid")
	}
	rawPermissions, ok := claims[p.Provider.PermissionsClaimKey].([]any)
	if !ok {
		return nil, fmt.Errorf("oidc permissions claim could not be parsed")
	}
	var permissions []string
	for _, v := range rawPermissions {
		s, ok := v.(string)
		if ok {
			permissions = append(permissions, s)
		}
	}
	return &NotaryJWTClaims{
		Permissions: permissions,
		Email:       claims[p.Provider.EmailClaimKey].(string),
	}, nil
}

func verifyLocalJWT(ctx context.Context, p ProviderConfig, raw string) (*NotaryJWTClaims, error) {
	claims := localJWTClaims{}
	token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
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

	return &NotaryJWTClaims{
		Permissions:      claims.Permissions,
		Email:            claims.Email,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}
