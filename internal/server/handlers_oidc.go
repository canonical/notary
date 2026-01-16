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

		// Extract claims from ID token
		var claims struct {
			Sub   string `json:"sub"`
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to extract claims from id_token", err, env.SystemLogger)
			return
		}

		env.SystemLogger.Debug("OIDC user authenticated",
			zap.String("email", claims.Email),
			zap.String("subject", claims.Sub[:min(8, len(claims.Sub))]+"..."))

		// Try to find existing user by OIDC subject
		user, err := env.DB.GetUser(db.ByOIDCSubject(claims.Sub))
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusInternalServerError, "failed to query user", err, env.SystemLogger)
				return
			}

			// User not found by OIDC subject - check if email exists
			existingUserByEmail, emailErr := env.DB.GetUser(db.ByEmail(claims.Email))
			if emailErr == nil && existingUserByEmail != nil {
				// Email exists but OIDC subject doesn't match - prevent auto-linking for security
				env.SystemLogger.Warn("OIDC login attempted with email that matches existing local user",
					zap.String("email", claims.Email),
					zap.String("oidc_subject", claims.Sub[:min(8, len(claims.Sub))]+"..."))

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

			// Auto-provision new OIDC user with RoleReadOnly (ID=3)
			user, err = env.DB.CreateOIDCUser(claims.Email, claims.Sub, db.RoleReadOnly)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create OIDC user", err, env.SystemLogger)
				return
			}

			env.SystemLogger.Info("New OIDC user auto-provisioned",
				zap.String("email", claims.Email),
				zap.Int64("user_id", user.ID),
				zap.String("role", "RoleReadOnly"))
			env.AuditLogger.UserCreated(claims.Email, int(db.RoleReadOnly), logging.WithRequest(r))
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
