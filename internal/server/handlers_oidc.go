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

// LinkOIDC initiates the OIDC authentication flow for account linking
func LinkOIDC(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get current user from JWT
		claims, err := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}

		// Get user from database to get user ID
		user, err := env.DB.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get user", err, env.SystemLogger)
			return
		}

		// Check if user already has OIDC linked
		if user.HasOIDC() {
			writeError(w, http.StatusBadRequest, "OIDC account already linked", nil, env.SystemLogger)
			return
		}

		// Generate state and store it with user ID for linking
		state := generateRandomString(32)
		env.StateStore.StoreForLinking(state, r.UserAgent(), user.ID)

		env.SystemLogger.Debug("OIDC account linking initiated",
			zap.Int64("user_id", user.ID),
			zap.String("email", user.Email),
			zap.String("state", state[:8]+"..."))

		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		http.Redirect(w, r, env.OIDCConfig.OAuth2Config.AuthCodeURL(state, aud), http.StatusFound)
	}
}

// CallbackLinkOIDC handles the OIDC callback for account linking
func CallbackLinkOIDC(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		// Get state entry to check if it's a linking request
		stateEntry, valid := env.StateStore.Get(state, r.UserAgent())
		if !valid || stateEntry == nil {
			env.SystemLogger.Warn("OIDC linking callback with invalid state",
				zap.String("state_prefix", state[:min(8, len(state))]+"..."),
				zap.String("user_agent", r.UserAgent()))
			writeError(w, http.StatusBadRequest, "invalid or expired state parameter", nil, env.SystemLogger)
			return
		}

		// Verify this is a linking request
		if stateEntry.Type != "linking" || stateEntry.UserID == nil {
			env.SystemLogger.Warn("OIDC callback state is not for linking",
				zap.String("state_type", stateEntry.Type))
			writeError(w, http.StatusBadRequest, "invalid state type", nil, env.SystemLogger)
			return
		}

		// Delete state after validation
		env.StateStore.Delete(state)

		// Get current user from JWT to verify session is still valid
		claims, err := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Session expired. Please login and try again.", err, env.SystemLogger)
			return
		}

		user, err := env.DB.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get user", err, env.SystemLogger)
			return
		}

		// Verify user ID matches the one in state (prevent session hijacking)
		if user.ID != *stateEntry.UserID {
			env.SystemLogger.Warn("OIDC linking callback user ID mismatch",
				zap.Int64("user_id_from_state", *stateEntry.UserID),
				zap.Int64("user_id_from_session", user.ID))
			writeError(w, http.StatusForbidden, "User mismatch. Please try again.", nil, env.SystemLogger)
			return
		}

		// Exchange code for tokens
		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		oauth2Token, err := env.OIDCConfig.OAuth2Config.Exchange(r.Context(), code, aud)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to exchange oauth2 token", err, env.SystemLogger)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			writeError(w, http.StatusInternalServerError, "failed to get id_token", nil, env.SystemLogger)
			return
		}

		// Verify ID token
		verifier := env.OIDCConfig.OIDCProvider.Verifier(&oidc.Config{ClientID: env.OIDCConfig.OAuth2Config.ClientID})
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "failed to verify id_token", err, env.SystemLogger)
			return
		}

		// Extract all claims for debugging
		var allOIDCClaims map[string]interface{}
		if err := idToken.Claims(&allOIDCClaims); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to extract claims from id_token", err, env.SystemLogger)
			return
		}

		// Extract subject (always "sub" per OIDC spec)
		oidcSub, ok := allOIDCClaims["sub"].(string)
		if !ok || oidcSub == "" {
			env.SystemLogger.Error("OIDC ID token missing required 'sub' claim",
				zap.Any("all_claims", allOIDCClaims))
			writeError(w, http.StatusBadRequest, "ID token missing required 'sub' claim", nil, env.SystemLogger)
			return
		}

		// Check if this OIDC subject is already linked to another user
		existingUser, err := env.DB.GetUser(db.ByOIDCSubject(oidcSub))
		if err == nil && existingUser != nil {
			if existingUser.ID != user.ID {
				env.SystemLogger.Warn("OIDC subject already linked to different user",
					zap.String("oidc_subject", oidcSub[:min(8, len(oidcSub))]+"..."),
					zap.Int64("existing_user_id", existingUser.ID),
					zap.Int64("current_user_id", user.ID))
				writeError(w, http.StatusConflict, "This OIDC account is already linked to another user", nil, env.SystemLogger)
				return
			}
			// Already linked to same user - this is fine, redirect to settings
			http.Redirect(w, r, "/settings/account?message=already_linked", http.StatusFound)
			return
		}

		// Link OIDC account
		if err := env.DB.LinkOIDCAccount(user.ID, oidcSub); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to link OIDC account", err, env.SystemLogger)
			return
		}

		env.SystemLogger.Info("OIDC account linked successfully",
			zap.Int64("user_id", user.ID),
			zap.String("email", user.Email),
			zap.String("oidc_subject", oidcSub[:min(8, len(oidcSub))]+"..."))

		env.AuditLogger.UserUpdated(user.Email, "oidc_linked", logging.WithRequest(r))

		http.Redirect(w, r, "/settings/account?message=link_success", http.StatusFound)
	}
}

// UnlinkOIDC removes the OIDC link from a user account
func UnlinkOIDC(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get current user from JWT
		claims, err := getClaimsFromCookie(r, env.JWTSecret, env.OIDCConfig)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized", err, env.SystemLogger)
			return
		}

		user, err := env.DB.GetUser(db.ByEmail(claims.Email))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get user", err, env.SystemLogger)
			return
		}

		// Check if user has a password (prevent lockout)
		if !user.HasPassword() {
			writeError(w, http.StatusBadRequest, "Cannot unlink OIDC account without a local password. Please set a password first.", nil, env.SystemLogger)
			return
		}

		// Check if user has OIDC linked
		if !user.HasOIDC() {
			writeError(w, http.StatusBadRequest, "No OIDC account linked", nil, env.SystemLogger)
			return
		}

		// Unlink OIDC account
		if err := env.DB.UnlinkOIDCAccount(user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to unlink OIDC account", err, env.SystemLogger)
			return
		}

		env.SystemLogger.Info("OIDC account unlinked",
			zap.Int64("user_id", user.ID),
			zap.String("email", user.Email))

		env.AuditLogger.UserUpdated(user.Email, "oidc_unlinked", logging.WithRequest(r))

		err = writeResponse(w, SuccessResponse{Message: "OIDC account unlinked successfully"}, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
