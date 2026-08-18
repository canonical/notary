package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/backends/observability/log"
	"github.com/canonical/notary/internal/db"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// resolveRoleFromClaims maps an ID token claim onto a Notary role using the
// provider's configured mapping. Mappings live only in the config file, never
// in the database, so an operator can always recover access by editing config.
// Unmapped or unmatched claims fall back to the least privileged role.
func resolveRoleFromClaims(mapping authentication.RoleMapping, claims map[string]any) db.RoleID {
	if mapping.Claim == "" || len(mapping.Values) == 0 {
		return db.RoleReadOnly
	}

	var claimValues []string
	switch value := claims[mapping.Claim].(type) {
	case string:
		claimValues = []string{value}
	case []any:
		for _, item := range value {
			if str, ok := item.(string); ok {
				claimValues = append(claimValues, str)
			}
		}
	}

	// The most privileged match wins, so membership in several mapped groups
	// grants the union of their permissions rather than depending on claim order.
	role := db.RoleReadOnly
	matched := false
	for _, claimValue := range claimValues {
		mapped, ok := mapping.Values[claimValue]
		if !ok {
			continue
		}
		mappedRole := db.RoleID(mapped)
		if !RoleID(mappedRole).IsValid() {
			continue
		}
		if !matched || mappedRole < role {
			role = mappedRole
			matched = true
		}
	}
	return role
}

func LoginOIDC(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerName := r.URL.Query().Get("provider")
		provider, ok := env.AuthnRepository.Get(providerName)
		if !ok {
			env.SystemLogger.Warn("OIDC login requested for unknown provider",
				zap.String("provider", providerName))
			writeResponse(w, http.StatusBadRequest, "unknown identity provider", nil, env.SystemLogger)
			return
		}

		state := generateRandomString(32)
		codeVerifier := oauth2.GenerateVerifier()

		env.StateStore.StorePKCE(state, r.UserAgent(), codeVerifier, provider.Name)

		env.SystemLogger.Debug("OIDC login initiated",
			zap.String("state", state[:8]+"..."),
			zap.String("provider", provider.Name),
			zap.String("user_agent", r.UserAgent()))

		aud := oauth2.SetAuthURLParam("audience", provider.Audience)
		authURL := provider.OAuth2Config.AuthCodeURL(state, aud, oauth2.S256ChallengeOption(codeVerifier))
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func CallbackOIDC(env *HandlerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		stateEntry, stateValid := env.StateStore.Consume(state, r.UserAgent())
		if !stateValid {
			env.SystemLogger.Warn("OIDC callback with invalid state",
				zap.String("state_prefix", state[:min(8, len(state))]+"..."),
				zap.String("user_agent", r.UserAgent()),
				zap.String("remote_addr", r.RemoteAddr))
			env.AuditLogger.OIDCLoginFailed("invalid or expired state parameter",
				log.WithRequest(r),
				log.WithReason("invalid or expired state parameter"),
			)
			writeResponse(w, http.StatusBadRequest, "invalid or expired state parameter", nil, env.SystemLogger)
			return
		}

		env.SystemLogger.Debug("OIDC callback state validated successfully",
			zap.String("user_agent", r.UserAgent()))

		provider, ok := env.AuthnRepository.Get(stateEntry.Provider)
		if !ok {
			env.SystemLogger.Error("OIDC callback for a provider that is no longer configured",
				zap.String("provider", stateEntry.Provider))
			writeResponse(w, http.StatusBadRequest, "unknown identity provider", nil, env.SystemLogger)
			return
		}

		exchangeOpts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", provider.Audience)}
		if stateEntry.CodeVerifier != "" {
			exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(stateEntry.CodeVerifier))
		}
		oauth2Token, err := provider.OAuth2Config.Exchange(r.Context(), code, exchangeOpts...)
		if err != nil {
			env.SystemLogger.Error("failed to exchange oauth2 token", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			env.SystemLogger.Error("failed to get id_token from oauth2 token response")
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		verifier := provider.OIDCProvider.Verifier(&oidc.Config{ClientID: provider.OAuth2Config.ClientID})
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			env.AuditLogger.OIDCLoginFailed("failed to verify id_token",
				log.WithRequest(r),
				log.WithReason("failed to verify id_token"),
			)
			env.SystemLogger.Warn("failed to verify id_token", zap.Error(err))
			writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
			return
		}

		// Extract all claims for debugging
		var allClaims map[string]interface{}
		if err := idToken.Claims(&allClaims); err != nil {
			env.SystemLogger.Error("failed to extract claims from id_token", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		// Extract subject (always "sub" per OIDC spec)
		sub, ok := allClaims["sub"].(string)
		if !ok || sub == "" {
			env.SystemLogger.Error("OIDC ID token missing required 'sub' claim",
				zap.Any("all_claims", allClaims))
			writeResponse(w, http.StatusBadRequest, "invalid identity token", nil, env.SystemLogger)
			return
		}

		// Extract email using configured claim key
		email, _ := allClaims[provider.EmailClaimKey].(string)

		// Log helpful message if email is missing
		if email == "" {
			env.SystemLogger.Warn("OIDC ID token missing email claim - user will be created without email",
				zap.String("expected_claim_key", provider.EmailClaimKey),
				zap.Any("available_claims", allClaims),
				zap.String("hint", "To include email: 1) Ensure email scope is requested in OIDC config, 2) Check IDP settings, 3) Verify email_claim_key matches your IDP's claim field name"))
		}

		env.SystemLogger.Debug("OIDC user authenticated",
			zap.String("email", email),
			zap.String("subject", sub[:min(8, len(sub))]+"..."),
			zap.String("provider", provider.Name),
			zap.String("email_claim_key", provider.EmailClaimKey),
			zap.Any("all_claims", allClaims))

		// Try to find existing user by OIDC identity. A subject is only unique
		// within the issuer that minted it, so both halves are used.
		user, err := env.Database.GetUser(db.ByOIDCIdentity(idToken.Issuer, sub))
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				env.SystemLogger.Error("failed to query user", zap.Error(err))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
				return
			}

			// User not found by OIDC subject - check if email exists (only if email is provided)
			if email != "" {
				existingUserByEmail, emailErr := env.Database.GetUser(db.ByEmail(email))
				if emailErr == nil && existingUserByEmail != nil {
					// Email exists but OIDC subject doesn't match - prevent auto-linking for security
					env.SystemLogger.Warn("OIDC login attempted with email that matches existing local user",
						zap.String("email", email),
						zap.String("oidc_subject", sub[:min(8, len(sub))]+"..."))

					errorPage := `
<!DOCTYPE html>
<html>
<head><title>Account Linking Required</title></head>
<body>
	<h1>Email Already Registered</h1>
	<p>This email address is already associated with a local account.</p>
	<p>To use OIDC authentication with this account:</p>
	<ol>
		<li>Login with your local password</li>
		<li>Navigate to Account Settings</li>
		<li>Click "Link OIDC Account"</li>
	</ol>
	<a href="/login">Return to Login</a>
</body>
</html>`
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusConflict)
					if _, writeErr := w.Write([]byte(errorPage)); writeErr != nil {
						env.SystemLogger.Error("Failed to write OIDC error page", zap.Error(writeErr))
					}
					return
				}
			}

			// Auto-provision new OIDC user
			// Email is optional - the OIDC subject is the primary identifier
			emailOrPlaceholder := email
			if emailOrPlaceholder == "" {
				emailOrPlaceholder = "(none)"
			}

			// Determine role: the provider's configured claim mapping decides,
			// falling back to read-only. The first user in the system is always
			// an admin, so a deployment can never lock itself out.
			numUsers, countErr := env.Database.NumUsers()
			if countErr != nil {
				env.SystemLogger.Error("failed to check user count", zap.Error(countErr))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
				return
			}
			role := resolveRoleFromClaims(provider.RoleMapping, allClaims)
			if numUsers == 0 {
				role = db.RoleAdmin
				env.SystemLogger.Info("First user in system — granting admin role via OIDC",
					zap.String("email", emailOrPlaceholder),
					zap.String("subject", sub))
			}

			env.SystemLogger.Info("Auto-provisioning new OIDC user",
				zap.String("email", emailOrPlaceholder),
				zap.String("subject", sub),
				zap.Int("role_id", int(role)))

			user, err = env.Database.CreateOIDCUser(email, idToken.Issuer, sub, role)
			if err != nil {
				env.SystemLogger.Error("Failed to create OIDC user",
					zap.Error(err),
					zap.String("email", emailOrPlaceholder),
					zap.String("subject", sub))
				writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
				return
			}

			env.SystemLogger.Info("New OIDC user auto-provisioned successfully",
				zap.String("email", emailOrPlaceholder),
				zap.Int64("user_id", user.ID),
				zap.Int("role_id", int(role)))
			env.AuditLogger.UserCreated(emailOrPlaceholder, int(role), log.WithRequest(r))
		}

		// Generate local JWT with user's database role permissions
		jwt, err := generateJWT(user.ID, user.Email, env.Database.JWTSecret, RoleID(user.RoleID))
		if err != nil {
			env.SystemLogger.Error("failed to generate JWT", zap.Error(err))
			writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
			return
		}

		// Set JWT cookie (same as local login)
		http.SetCookie(w, &http.Cookie{
			Name:     CookieSessionTokenKey,
			Value:    jwt,
			HttpOnly: true,
			Secure:   true,
			Expires:  time.Now().Add(2 * time.Hour),
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})

		env.AuditLogger.TokenCreated(user.Email, log.WithRequest(r))
		env.AuditLogger.LoginSuccess(user.Email, log.WithRequest(r))

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
