package authentication

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/golang-jwt/jwt/v5"
)

// SetUpJWTSecret loads the JWT secret into database.JWTSecret. If none exists it
// generates one and stores it. On a fresh cluster several members can race to
// create the first secret; the losers reload the winner's value.
func SetUpJWTSecret(database *db.DatabaseRepository) error {
	const attempts = 8
	var candidate []byte
	var last error

	for i := range attempts {
		jwtSecret, err := database.GetJWTSecret()
		switch {
		case err == nil:
			database.JWTSecret = jwtSecret
			return nil
		case errors.Is(err, db.ErrNotFound):
		case errors.Is(err, db.ErrInternal):
			// A contended read can surface this way, same as the create below.
			last = err
			time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
			continue
		default:
			return fmt.Errorf("failed to get JWT secret: %w", err)
		}

		if candidate == nil {
			candidate, err = generateJWTSecret()
			if err != nil {
				return err
			}
		}

		switch err = database.CreateJWTSecret(candidate); {
		case err == nil:
			database.JWTSecret = candidate
			return nil
		case errors.Is(err, db.ErrAlreadyExists):
			// Another member won, so its value is already stored. Reload at once.
			last = err
		case errors.Is(err, db.ErrInternal):
			last = err
			time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
		default:
			return fmt.Errorf("failed to store JWT secret: %w", err)
		}
	}
	return fmt.Errorf("failed to set up JWT secret: %w", last)
}

// This secret should be generated once and stored in the database, encrypted.
func generateJWTSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return bytes, nil
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

	if issVal, ok := claims["iss"].(string); !ok || issVal == "" || (p.Provider.Issuer != "" && issVal != p.Provider.Issuer) {
		return nil, fmt.Errorf("oidc token issuer mismatch or missing")
	}

	expectedAud := p.Provider.Audience
	if expectedAud == "" && p.Provider.OAuth2Config != nil {
		expectedAud = p.Provider.OAuth2Config.ClientID
	}
	if expectedAud != "" {
		audOk := false
		switch aud := claims["aud"].(type) {
		case string:
			audOk = (aud == expectedAud)
		case []any:
			for _, v := range aud {
				if s, ok := v.(string); ok && s == expectedAud {
					audOk = true
					break
				}
			}
		case []string:
			if slices.Contains(aud, expectedAud) {
				audOk = true
			}
		}
		if !audOk {
			return nil, fmt.Errorf("oidc token audience invalid")
		}
	}
	email, _ := claims[p.Provider.EmailClaimKey].(string)
	if email == "" {
		return nil, fmt.Errorf("oidc email claim missing or invalid")
	}
	return &NotaryJWTClaims{
		Email: email,
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
		Email:            claims.Email,
		RoleID:           claims.RoleID,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}
