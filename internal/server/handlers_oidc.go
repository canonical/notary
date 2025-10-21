package server

import (
	"context"
	"net/http"
)

func LoginOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, env.OIDCConfig.OIDCConfig.AuthCodeURL(env.State), http.StatusFound)
	}
}

func CallbackOIDC(env *HandlerOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		oauth2Token, err := env.OIDCConfig.OIDCConfig.Exchange(context.Background(), code)
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			writeError(w, http.StatusInternalServerError, "failed to get id_token", err, env.Logger)
			return
		}

		idtoken, err := env.OIDCConfig.Verifier.Verify(context.Background(), rawIDToken)
		var claims struct {
			Email string `json:"email"`
			Sub   string `json:"sub"`
		}
		if err := idtoken.Claims(&claims); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to unmarshal claims", err, env.Logger)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     CookieSessionTokenKey,
			Value:    rawIDToken,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     CookieHasSessionKey,
			Value:    "true",
			HttpOnly: false,
			Secure:   true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
