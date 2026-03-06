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

	StateStore *StateStore
}

type Server struct {
	*http.Server
}

type middleware func(http.Handler) http.Handler

type NotificationKey int
