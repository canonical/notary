package server

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func LoginOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		http.Redirect(w, r, env.OIDCConfig.OAuth2Config.AuthCodeURL(env.State, aud), http.StatusFound)
	}
}

func CallbackOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if state != env.State {
			writeError(w, http.StatusBadRequest, "invalid state", nil, env.Logger)
			return
		}

		aud := oauth2.SetAuthURLParam("audience", env.OIDCConfig.Audience)
		oauth2Token, err := env.OIDCConfig.OAuth2Config.Exchange(context.Background(), code, aud)
		rawAccessToken := oauth2Token.AccessToken
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			writeError(w, http.StatusInternalServerError, "failed to get id_token", err, env.Logger)
			return
		}

		verifier := env.OIDCConfig.OIDCProvider.Verifier(&oidc.Config{ClientID: env.OIDCConfig.OAuth2Config.ClientID})
		_, err = verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify id_token", err, env.Logger)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     CookieSessionTokenKey,
			Value:    rawAccessToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
