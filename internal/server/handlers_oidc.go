package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/logging"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func LoginOIDC(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := generateRandomString(32)

		env.StateStore.Store(state, r.UserAgent())

		env.SystemLogger.Debug("OIDC login initiated",
			zap.String("state", state[:8]+"..."),
			zap.String("user_agent", r.UserAgent()))

		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		http.Redirect(w, r, env.OIDCConfig.OAuth2Config.AuthCodeURL(state, aud), http.StatusFound)
	}
}

func CallbackOIDC(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if !env.StateStore.Validate(state, r.UserAgent()) {
			env.SystemLogger.Warn("OIDC callback with invalid state",
				zap.String("state_prefix", state[:min(8, len(state))]+"..."),
				zap.String("user_agent", r.UserAgent()),
				zap.String("remote_addr", r.RemoteAddr))
			writeError(w, http.StatusBadRequest, "invalid or expired state parameter", nil, env.SystemLogger)
			return
		}

		env.SystemLogger.Debug("OIDC callback state validated successfully",
			zap.String("user_agent", r.UserAgent()))

		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		oauth2Token, err := env.OIDCConfig.OAuth2Config.Exchange(r.Context(), code, aud)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to exchange oauth2 token", err, env.SystemLogger)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			writeError(w, http.StatusInternalServerError, "failed to get id_token", err, env.SystemLogger)
			return
		}

		verifier := env.OIDCConfig.OIDCProvider.Verifier(&oidc.Config{ClientID: env.OIDCConfig.OAuth2Config.ClientID})
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "failed to verify id_token", err, env.SystemLogger)
			return
		}

		// Extract all claims for debugging
		var allClaims map[string]interface{}
		if err := idToken.Claims(&allClaims); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to extract claims from id_token", err, env.SystemLogger)
			return
		}

		// Extract subject (always "sub" per OIDC spec)
		sub, ok := allClaims["sub"].(string)
		if !ok || sub == "" {
			env.SystemLogger.Error("OIDC ID token missing required 'sub' claim",
				zap.Any("all_claims", allClaims))
			writeError(w, http.StatusBadRequest, "ID token missing required 'sub' claim", nil, env.SystemLogger)
			return
		}

		// Extract email using configured claim key
		email, _ := allClaims[env.OIDCConfig.EmailClaimKey].(string)

		// Log helpful message if email is missing
		if email == "" {
			env.SystemLogger.Warn("OIDC ID token missing email claim - user will be created without email",
				zap.String("expected_claim_key", env.OIDCConfig.EmailClaimKey),
				zap.Any("available_claims", allClaims),
				zap.String("hint", "To include email: 1) Ensure email scope is requested in OIDC config, 2) Check IDP settings, 3) Verify email_claim_key matches your IDP's claim field name"))
		}

		env.SystemLogger.Debug("OIDC user authenticated",
			zap.String("email", email),
			zap.String("subject", sub[:min(8, len(sub))]+"..."),
			zap.String("email_claim_key", env.OIDCConfig.EmailClaimKey),
			zap.Any("all_claims", allClaims))

		// Try to find existing user by OIDC subject
		user, err := env.DB.GetUser(db.ByOIDCSubject(sub))
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusInternalServerError, "failed to query user", err, env.SystemLogger)
				return
			}

			// User not found by OIDC subject - check if email exists (only if email is provided)
			if email != "" {
				existingUserByEmail, emailErr := env.DB.GetUser(db.ByEmail(email))
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
					w.Write([]byte(errorPage))
					return
				}
			}

			// Auto-provision new OIDC user with RoleReadOnly (ID=3)
			// Email is optional - the OIDC subject is the primary identifier
			emailOrPlaceholder := email
			if emailOrPlaceholder == "" {
				emailOrPlaceholder = "(none)"
			}

			env.SystemLogger.Info("Auto-provisioning new OIDC user",
				zap.String("email", emailOrPlaceholder),
				zap.String("subject", sub),
				zap.Int("role_id", int(db.RoleReadOnly)))

			user, err = env.DB.CreateOIDCUser(email, sub, db.RoleReadOnly)
			if err != nil {
				env.SystemLogger.Error("Failed to create OIDC user",
					zap.Error(err),
					zap.String("email", emailOrPlaceholder),
					zap.String("subject", sub))
				writeError(w, http.StatusInternalServerError, "failed to create OIDC user", err, env.SystemLogger)
				return
			}

			env.SystemLogger.Info("New OIDC user auto-provisioned successfully",
				zap.String("email", emailOrPlaceholder),
				zap.Int64("user_id", user.ID),
				zap.String("role", "RoleReadOnly"))
			env.AuditLogger.UserCreated(emailOrPlaceholder, int(db.RoleReadOnly), logging.WithRequest(r))
		}

		// Generate local JWT with user's database role permissions
		jwt, err := generateJWT(user.ID, user.Email, env.JWTSecret, RoleID(user.RoleID))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate JWT", err, env.SystemLogger)
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

		env.AuditLogger.TokenCreated(user.Email, logging.WithRequest(r))
		env.AuditLogger.LoginSuccess(user.Email, logging.WithRequest(r))

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
