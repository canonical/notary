package server

import (
	"net/http"

	"github.com/canonical/notary/internal/config"
)

const (
	CookieSessionTokenKey = "user_token"
)

type ServerOpts struct {
	*config.AppConfig
	*config.AppEnvironment
}

// HandlerDependencies holds the dependencies to be injected into the HTTP handlers for use during
// request processing.
type HandlerDependencies struct {
	*config.AppConfig
	*config.AppEnvironment

	StateStore OAuthStateStore
}

type Server struct {
	*http.Server
}

// OAuthStateStore holds OIDC login CSRF state. Production uses dqlite so a
// callback can land on any cluster member.
type OAuthStateStore interface {
	Store(state string, userAgent string)
	Validate(state string, userAgent string) bool
	Cleanup()
	Size() int
}

type middleware func(http.Handler) http.Handler

type NotificationKey int
