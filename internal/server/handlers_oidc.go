package server

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func LoginOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := generateRandomString(32)
		
		env.StateStore.Store(state, r.UserAgent())
		
		env.Logger.Debug("OIDC login initiated",
			zap.String("state", state[:8]+"..."),
			zap.String("user_agent", r.UserAgent()))
		
		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		http.Redirect(w, r, env.OIDCConfig.OAuth2Config.AuthCodeURL(state, aud), http.StatusFound)
	}
}

func CallbackOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if !env.StateStore.Validate(state, r.UserAgent()) {
			env.Logger.Warn("OIDC callback with invalid state",
				zap.String("state_prefix", state[:min(8, len(state))]+"..."),
				zap.String("user_agent", r.UserAgent()),
				zap.String("remote_addr", r.RemoteAddr))
			writeError(w, http.StatusBadRequest, "invalid or expired state parameter", nil, env.Logger)
			return
		}
		
		env.Logger.Debug("OIDC callback state validated successfully",
			zap.String("user_agent", r.UserAgent()))

        aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
        oauth2Token, err := env.OIDCConfig.OAuth2Config.Exchange(r.Context(), code, aud)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to exchange oauth2 token", err, env.Logger)
			return
		}
		rawAccessToken := oauth2Token.AccessToken
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

        if !ok {
            writeError(w, http.StatusInternalServerError, "failed to get id_token", err, env.Logger)
			return
		}

		verifier := env.OIDCConfig.OIDCProvider.Verifier(&oidc.Config{ClientID: env.OIDCConfig.OAuth2Config.ClientID})
        _, err = verifier.Verify(r.Context(), rawIDToken)
        if err != nil {
            writeError(w, http.StatusUnauthorized, "failed to verify id_token", err, env.Logger)
			return
		}
        expiry := oauth2Token.Expiry
        if expiry.IsZero() {
            expiry = time.Now().Add(2 * time.Hour)
        }
        http.SetCookie(w, &http.Cookie{
			Name:     CookieSessionTokenKey,
			Value:    rawAccessToken,
			HttpOnly: true,
			Secure:   true,
            Expires:  expiry,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
